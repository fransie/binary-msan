#include <irdb-elfdep>
#include <unistd.h>
#include "RuntimeLib.h"
#include "Utils.h"
#include "EflagsHandler.h"
#include "FunctionAnalysis.h"
#include "MSan.h"
#include "LeaHandler.h"
#include "JumpHandler.h"
#include "BasicInstructionHandler.h"
#include "MemoryAccessHandler.h"
#include "MovHandler.h"
#include "StackVariableHandler.h"

using namespace IRDB_SDK;
using namespace std;

MSan::MSan(FileIR_t *fileIR) : Transform_t(fileIR) {
    functionHandlers.push_back(make_unique<StackVariableHandler>(fileIR));
    instructionHandlers.push_back(make_unique<MemoryAccessHandler>(fileIR));
    instructionHandlers.push_back(make_unique<MovHandler>(fileIR));
    instructionHandlers.push_back(make_unique<EflagsHandler>(fileIR));
    instructionHandlers.push_back(make_unique<JumpHandler>(fileIR));
    instructionHandlers.push_back(make_unique<BasicInstructionHandler>(fileIR));
    instructionHandlers.push_back(make_unique<LeaHandler>(fileIR));
}

bool MSan::executeStep() {
    registerDependencies();
    Function_t* mainFunction = nullptr;
    unique_ptr<FunctionAnalysis> mainFunctionAnalysis = nullptr;
    auto functions = getFileIR()->getFunctions();
    for (auto const &function : functions){
        if(function->getName() == "main"){
            mainFunction = function;
            mainFunctionAnalysis = make_unique<FunctionAnalysis>(mainFunction);
            break;
        }
    }
    if(!mainFunction){
        cout << "No main function detected." << endl;
    }

    const set<Instruction_t*> originalInstructions(mainFunction->getInstructions().begin(), mainFunction->getInstructions().end());
    for (auto instruction : originalInstructions){
        auto d = instruction->getDisassembly();
        for (auto&& handler : instructionHandlers){
            if(handler->isResponsibleFor(instruction)){
                instruction = handler->instrument(instruction);
            }
        }
    }
    functionHandlers.at(0)->instrument(mainFunctionAnalysis);

    // assume RBP and RSP registers are initialised upon entry of main function
    initGpRegisters(mainFunction->getEntryPoint());

    // disable halt_on_error if required
    if(!halt_on_error){
        disableHaltOnError(mainFunction->getEntryPoint());
    }
    return true; //success
}

void MSan::initGpRegisters(Instruction_t *instruction){
    string instrumentation = string() +
            Utils::getStateSavingInstrumentation() +
                             "call 0\n" +
            Utils::getStateRestoringInstrumentation();
    const auto new_instr = IRDB_SDK::insertAssemblyInstructionsAfter(getFileIR(), instruction, instrumentation, {});
    auto calls = DisassemblyService::getCallInstructionPosition(new_instr);
	new_instr[calls[0]]->setTarget(RuntimeLib::initGpRegisters);
}

void MSan::registerDependencies(){
    auto elfDeps = ElfDependencies_t::factory(getFileIR());
    // TODO: fix absolute paths

    const string runtimeLibPath = "/home/franzi/Documents/binary-msan/plugins_install/";
    elfDeps->prependLibraryDepedencies(runtimeLibPath + "libinterface.so");
    RuntimeLib::regToRegShadowCopy = elfDeps->appendPltEntry("regToRegShadowCopy");
    RuntimeLib::checkRegIsInit = elfDeps->appendPltEntry("checkRegIsInit");
    RuntimeLib::memToRegShadowCopy = elfDeps->appendPltEntry("memToRegShadowCopy");
    RuntimeLib::checkEflags = elfDeps->appendPltEntry("checkEflags");
    RuntimeLib::initGpRegisters = elfDeps->appendPltEntry("initGpRegisters");
    RuntimeLib::regToMemShadowCopy = elfDeps->appendPltEntry("regToMemShadowCopy");
    RuntimeLib::isRegFullyDefined = elfDeps->appendPltEntry("isRegFullyDefined");
    RuntimeLib::isMemFullyDefined = elfDeps->appendPltEntry("isMemFullyDefined");
    RuntimeLib::isRegOrRegFullyDefined = elfDeps->appendPltEntry("isRegOrRegFullyDefined");
    RuntimeLib::isRegOrMemFullyDefined = elfDeps->appendPltEntry("isRegOrMemFullyDefined");
    RuntimeLib::setEflags = elfDeps->appendPltEntry("setEflags");
    RuntimeLib::setRegShadow = elfDeps->appendPltEntry("setRegShadow");
    RuntimeLib::setMemShadow = elfDeps->appendPltEntry("setMemShadow");
    RuntimeLib::unpoisonUpper4Bytes = elfDeps->appendPltEntry("unpoisonUpper4Bytes");
    RuntimeLib::propagateRegOrRegShadow = elfDeps->appendPltEntry("propagateRegOrRegShadow");
    RuntimeLib::propagateRegOrMemShadow = elfDeps->appendPltEntry("propagateRegOrMemShadow");
    RuntimeLib::propagateMemOrRegShadow = elfDeps->appendPltEntry("propagateMemOrRegShadow");

    RuntimeLib::msan_check_mem_is_initialized = elfDeps->appendPltEntry("__msan_check_mem_is_initialized");
    RuntimeLib::msan_poison_stack = elfDeps->appendPltEntry("__msan_poison_stack");
    RuntimeLib::msan_set_keep_going = elfDeps->appendPltEntry("__msan_set_keep_going");
    RuntimeLib::msan_unpoison = elfDeps->appendPltEntry("__msan_unpoison");

    const string compilerRtPath = "/home/franzi/Documents/binary-msan/clang_msan_libs/";
    elfDeps->prependLibraryDepedencies(compilerRtPath + "libclang_rt.msan_cxx-x86_64.so");
    elfDeps->prependLibraryDepedencies(compilerRtPath + "libclang_rt.msan-x86_64.so");

    getFileIR()->assembleRegistry();
}

bool MSan::parseArgs(std::vector<std::string> step_args) {
    return true;
}

// https://www.gnu.org/savannah-checkouts/gnu/libc/manual/html_node/Example-of-Getopt.html
bool MSan::parseArgs(int argc, char **argv) {
    int c;
    opterr = 0;
    while ((c = getopt (argc, argv, "k")) != -1){
        switch (c)
        {
            case 'k':
                halt_on_error = false;
                std::cout << "Msan will keep going after warnings." << std::endl;
                break;
            case '?':
                if (optopt == 'c')
                    fprintf (stderr, "Option -%c requires an argument.\n", optopt);
                else if (isprint (optopt))
                    fprintf (stderr, "Unknown option `-%c'.\n", optopt);
                else
                    fprintf (stderr,
                             "Unknown option character `\\x%x'.\n",
                             optopt);
                return true;
            default:
                std::cerr << "Error parsing arguments." << std::endl;
                return false;
        }
    }
    return true;
}

void MSan::disableHaltOnError(IRDB_SDK::Instruction_t *instruction) {
    string instrumentation = string() +
            Utils::getStateSavingInstrumentation() +
                             "mov rdi, 1\n" +
                             "call 0\n" +
            Utils::getStateRestoringInstrumentation();
    const auto new_instr = IRDB_SDK::insertAssemblyInstructionsAfter(getFileIR(), instruction, instrumentation, {});
    auto calls = DisassemblyService::getCallInstructionPosition(new_instr);
	new_instr[calls[0]]->setTarget(RuntimeLib::msan_set_keep_going);
}

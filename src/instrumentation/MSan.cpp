#include <irdb-elfdep>
#include <unistd.h>
#include "RuntimeLib.h"
#include "Utils.h"
#include "EflagsHandler.h"
#include "FunctionAnalysis.h"
#include "MSan.h"
#include "LeaHandler.h"
#include "ControlFlowHandler.h"
#include "BinaryArithmeticHandler.h"
#include "BinaryLogicHandler.h"
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
    instructionHandlers.push_back(make_unique<ControlFlowHandler>(fileIR));
    instructionHandlers.push_back(make_unique<BinaryArithmeticHandler>(fileIR));
    instructionHandlers.push_back(make_unique<BinaryLogicHandler>(fileIR));
    instructionHandlers.push_back(make_unique<LeaHandler>(fileIR));
}

bool MSan::executeStep() {
    registerDependencies();
    vector<unique_ptr<FunctionAnalysis>> functionAnalyses = {};
    unique_ptr<FunctionAnalysis> mainFunctionAnalysis = nullptr;
    auto functions = getFileIR()->getFunctions();
    for (auto const &function: functions) {
        auto analysis = make_unique<FunctionAnalysis>(function);
        functionAnalyses.push_back(move(analysis));
        if (function->getName() == "main") {
            mainFunctionAnalysis = make_unique<FunctionAnalysis>(function);
        }
    }

    for (auto &analysis : functionAnalyses){
        auto func = analysis->getFunction();
        const set<Instruction_t *> originalInstructions(func->getInstructions().begin(), func->getInstructions().end());
        for (auto instruction: originalInstructions) {
            for (auto &&handler: instructionHandlers) {
                if (handler->isResponsibleFor(instruction)) {
                    instruction = handler->instrument(instruction);
                }
            }
        }
    }
    for (auto &analysis : functionAnalyses) {
        // Zipr returns one 'ThisIsNotAFunction' object, do not instrument it.
        if(analysis->getFunction()->getEntryPoint() == nullptr){
            continue;
        }
        functionHandlers.at(0)->instrument(analysis);
    }

    if (!mainFunctionAnalysis) {
        cout << "No main function detected. Options left out." << endl;
    } else {
        instrumentOptions(mainFunctionAnalysis->getFunction()->getEntryPoint());
    }
    return true; //success
}


void MSan::registerDependencies() {
    auto elfDeps = ElfDependencies_t::factory(getFileIR());

    auto binmsanHome = std::getenv("BINMSAN_HOME");
    if(!binmsanHome){
        throw logic_error("Env variable BINMSAN_HOME is missing!");
    }
    auto binmsanHomeString = std::string(binmsanHome);
    auto runtimeLibPath = binmsanHomeString + "/plugins_install/";
    elfDeps->prependLibraryDepedencies(runtimeLibPath + "libbinmsan_lib.so");

    const string compilerRtPath =  binmsanHomeString + "/llvm_shared_msan_lib/";
    elfDeps->prependLibraryDepedencies(compilerRtPath + "libclang_rt.msan_cxx-x86_64.so");
    elfDeps->prependLibraryDepedencies(compilerRtPath + "libclang_rt.msan-x86_64.so");

    RuntimeLib::regToRegShadowCopy = elfDeps->appendPltEntry("regToRegShadowCopy");
    RuntimeLib::checkRegIsInit = elfDeps->appendPltEntry("checkRegIsInit");
    RuntimeLib::memToRegShadowCopy = elfDeps->appendPltEntry("memToRegShadowCopy");
    RuntimeLib::checkRflags = elfDeps->appendPltEntry("checkRflags");
    RuntimeLib::initGpRegisters = elfDeps->appendPltEntry("initGpRegisters");
    RuntimeLib::enableLogging = elfDeps->appendPltEntry("enableLogging");
    RuntimeLib::regToMemShadowCopy = elfDeps->appendPltEntry("regToMemShadowCopy");
    RuntimeLib::isRegFullyDefined = elfDeps->appendPltEntry("isRegFullyDefined");
    RuntimeLib::isMemFullyDefined = elfDeps->appendPltEntry("isMemFullyDefined");
    RuntimeLib::isRegOrRegFullyDefined = elfDeps->appendPltEntry("isRegOrRegFullyDefined");
    RuntimeLib::isRegOrMemFullyDefined = elfDeps->appendPltEntry("isRegOrMemFullyDefined");
    RuntimeLib::setRflags = elfDeps->appendPltEntry("setRflags");
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

    getFileIR()->assembleRegistry();
}

[[maybe_unused]] bool MSan::parseArgs(std::vector<std::string> step_args) {
    return true;
}

// https://www.gnu.org/savannah-checkouts/gnu/libc/manual/html_node/Example-of-Getopt.html
bool MSan::parseArgs(int argc, char **argv) {
    int c;
    opterr = 0;
    while ((c = getopt(argc, argv, "kl")) != -1) {
        switch (c) {
            case 'k':
                keep_going = true;
                break;
            case 'l':
                logging = true;
                break;
            case '?':
                if (optopt == 'c')
                    fprintf(stderr, "Option -%c requires an argument.\n", optopt);
                else if (isprint(optopt))
                    fprintf(stderr, "Unknown option `-%c'.\n", optopt);
                else
                    fprintf(stderr,
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

void MSan::instrumentOptions(IRDB_SDK::Instruction_t *instruction) {
    // Call to initGpRegisters: Assume RBP and RSP registers are initialised upon entry of main function
    string instrumentation = Utils::getStateSavingInstrumentation() + "call 0\n";
    std::vector<Instruction_t *> targets = {RuntimeLib::initGpRegisters};

    if (keep_going) {
        instrumentation = instrumentation + "mov rdi, 1\ncall 0\n";
        targets.push_back(RuntimeLib::msan_set_keep_going);
        std::cout << "Msan will keep going after warnings." << std::endl;
    }

    if (logging) {
        instrumentation = instrumentation + "call 0\n";
        targets.push_back(RuntimeLib::enableLogging);
        std::cout << "Logging enabled." << std::endl;
    }

    instrumentation = instrumentation + Utils::getStateRestoringInstrumentation();
    const auto new_instr = IRDB_SDK::insertAssemblyInstructionsAfter(getFileIR(), instruction, instrumentation, {});
    auto calls = DisassemblyService::getCallInstructionPosition(new_instr);
    for (size_t x = 0; x < calls.size(); x++) {
        new_instr[calls[x]]->setTarget(targets[x]);
    }
}
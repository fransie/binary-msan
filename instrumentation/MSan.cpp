//
// Created by Franziska Mäckel on 03.04.22.
//

#include "MSan.h"
#include "JumpHandler.h"
#include "MovHandler.h"
#include "StackVariableHandler.h"
#include "TestHandler.h"

using namespace IRDB_SDK;
using namespace std;

MSan::MSan(FileIR_t *fileIR)
        :
        Transform_t(fileIR) // init Transform_t class for insertAssembly and getFileIR
{
    registerDependencies();
    functionHandlers.push_back(make_unique<StackVariableHandler>());
    instructionHandlers.push_back(make_unique<MovHandler>(fileIR));
    instructionHandlers.push_back(make_unique<TestHandler>(fileIR));
    instructionHandlers.push_back(make_unique<JumpHandler>(fileIR));
}

bool MSan::executeStep()
{
    registerDependencies();
    Function_t* mainFunction = nullptr;
    auto functions = getFileIR()->getFunctions();
    for (auto const &function : functions){
        if(function->getName() == "main"){
            mainFunction = function;
            functionHandlers.at(0)->instrument(mainFunction);
            break;
        }
    }
    if(!mainFunction){
        cout << "No main function detected." << endl;
    }
    // assume RBP and RSP registers are initialised upon entry of main function
    initGpRegisters(mainFunction->getEntryPoint());

    // disable halt_on_error if required
    if(!halt_on_error){
        disableHaltOnError(mainFunction->getEntryPoint());
    }

    // loop over instructions and add handlers to common functions
    auto instructions = mainFunction->getInstructions();
    for (auto instruction : instructions){
        auto decodedInstruction = DecodedInstruction_t::factory(instruction);
        auto mnemonic = decodedInstruction->getMnemonic();

        for (auto&& handler : instructionHandlers){
            for (const auto& associatedInstruction : handler->getAssociatedInstructions())
            if(mnemonic == associatedInstruction){
                handler->instrument(instruction);
            }
        }
    }
    return true; //success
}

void MSan::initGpRegisters(Instruction_t *instruction){
    string instrumentation = string() +
                             Utils::getPushCallerSavedRegistersInstrumentation() +
                             "call 0\n" +
                             Utils::getPopCallerSavedRegistersInstrumentation();
    const auto new_instr = IRDB_SDK::insertAssemblyInstructionsAfter(getFileIR(), instruction, instrumentation, {});
    new_instr[11]->setTarget(RuntimeLib::initGpRegisters);
}

void MSan::registerDependencies(){
    auto elfDeps = ElfDependencies_t::factory(getFileIR());
    // TODO: fix absolute paths

    const string runtimeLibPath = "/home/franzi/Documents/binary-msan/plugins_install/";
    elfDeps->prependLibraryDepedencies(runtimeLibPath + "libinterface.so");
    RuntimeLib::regToRegShadowCopy = elfDeps->appendPltEntry("_Z18regToRegShadowCopyiii");
    RuntimeLib::defineRegShadow = elfDeps->appendPltEntry("_Z15defineRegShadowii");
    RuntimeLib::defineMemShadow = elfDeps->appendPltEntry("_Z15defineMemShadowmi");
    RuntimeLib::checkRegIsInit = elfDeps->appendPltEntry("_Z14checkRegIsInitii");
    RuntimeLib::memToRegShadowCopy = elfDeps->appendPltEntry("_Z18memToRegShadowCopyiim");
    RuntimeLib::setFlagsAfterTest_Reg = elfDeps->appendPltEntry("_Z21setFlagsAfterTest_Regii");
    RuntimeLib::setFlagsAfterTest_RegReg = elfDeps->appendPltEntry("_Z24setFlagsAfterTest_RegRegiii");
    RuntimeLib::checkEflags = elfDeps->appendPltEntry("_Z11checkEflagsv");
    RuntimeLib::initGpRegisters = elfDeps->appendPltEntry("_Z15initGpRegistersv");
    RuntimeLib::regToMemShadowCopy = elfDeps->appendPltEntry("_Z18regToMemShadowCopyiim");
    RuntimeLib::disableHaltOnError = elfDeps->appendPltEntry("_Z18disableHaltOnErrorv");

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
                halt_on_error = true;
                std::cout << "Halt on error set to true." << std::endl;
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
                             Utils::getPushCallerSavedRegistersInstrumentation() +
                             "call 0\n" +
                             Utils::getPopCallerSavedRegistersInstrumentation();
    const auto new_instr = IRDB_SDK::insertAssemblyInstructionsAfter(getFileIR(), instruction, instrumentation, {});
    new_instr[11]->setTarget(RuntimeLib::disableHaltOnError);
}

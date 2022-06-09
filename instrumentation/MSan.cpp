//
// Created by Franziska Mäckel on 03.04.22.
//

#include "MSan.h"

using namespace IRDB_SDK;
using namespace std;

MSan::MSan(FileIR_t *fileIR)
        :
        Transform_t(fileIR) // init Transform_t class for insertAssembly and getFileIR
{
    registerDependencies();
    handlers.push_back(make_unique<MovHandler>(fileIR));
    handlers.push_back(make_unique<TestHandler>(fileIR));
    handlers.push_back(make_unique<JumpHandler>(fileIR));
}

bool MSan::executeStep()
{
    cout << "Starting msan step." << endl;
    registerDependencies();
    // get main function (for starters)
    Function_t* mainFunction = nullptr;
    auto functions = getFileIR()->getFunctions();
    for (auto const &function : functions){
        if(function->getName() == "main"){
            mainFunction = function;
            break;
        }
    }
    if(!mainFunction){
        cout << "No main function detected." << endl;
    }
    // assume RBP and RSP registers are initialised upon entry of main function
    initGpRegisters(mainFunction->getEntryPoint());

    // loop over instructions and add handlers to common functions
    auto instructions = mainFunction->getInstructions();
    for (auto instruction : instructions){
        auto decodedInstruction = DecodedInstruction_t::factory(instruction);
        auto decodedInstructionCopy = DecodedInstruction_t::factory(instruction);
        auto mnemonic = decodedInstruction->getMnemonic();

        for (auto&& handler : handlers){
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
    const auto new_instr = IRDB_SDK::insertAssemblyInstructionsBefore(getFileIR(), instruction, instrumentation, {});
    new_instr[10]->setTarget(RuntimeLib::initGpRegisters);
}

void MSan::registerDependencies(){
    auto elfDeps = ElfDependencies_t::factory(getFileIR());
    // TODO: fix absolute paths

    const string runtimeLibPath = "/home/franzi/Documents/binary-msan/plugins_install/";
    elfDeps->prependLibraryDepedencies(runtimeLibPath + "libinterface.so");
    RuntimeLib::regToRegShadowCopy = elfDeps->appendPltEntry("_Z18regToRegShadowCopyiii");
    RuntimeLib::defineRegShadow = elfDeps->appendPltEntry("_Z15defineRegShadowii");
    RuntimeLib::checkRegIsInit = elfDeps->appendPltEntry("_Z14checkRegIsInitii");
    RuntimeLib::memToRegShadowCopy = elfDeps->appendPltEntry("_Z18memToRegShadowCopyiim");
    RuntimeLib::setFlagsAfterTest_Reg = elfDeps->appendPltEntry("_Z21setFlagsAfterTest_Regii");
    RuntimeLib::setFlagsAfterTest_RegReg = elfDeps->appendPltEntry("_Z24setFlagsAfterTest_RegRegiii");
    RuntimeLib::checkEflags = elfDeps->appendPltEntry("_Z11checkEflagsv");
    RuntimeLib::initGpRegisters = elfDeps->appendPltEntry("_Z15initGpRegistersv");

    const string compilerRtPath = "/home/franzi/Documents/binary-msan/clang_msan_libs/";
    elfDeps->prependLibraryDepedencies(compilerRtPath + "libclang_rt.msan_cxx-x86_64.so");
    elfDeps->prependLibraryDepedencies(compilerRtPath + "libclang_rt.msan-x86_64.so");

    getFileIR()->assembleRegistry();
}

bool MSan::parseArgs(std::vector<std::string> step_args) {
    return true;
}

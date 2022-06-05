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

    // loop over instructions and add handlers to common functions
    auto instructions = mainFunction->getInstructions();
    for (auto instruction : instructions){
        auto decodedInstruction = DecodedInstruction_t::factory(instruction);
        auto decodedInstructionCopy = DecodedInstruction_t::factory(instruction);
        auto mnemonic = decodedInstruction->getMnemonic();
        for (auto&& handler : handlers){
            if(mnemonic == handler->getAssociatedInstruction()){
                handler->instrument(instruction);
            }
        }
    }
    return true; //success
}

/**
 * Takes an assembly add-instruction and inserts instrumentation before the instruction which
 * handles the shadow propagation.
 * @param instruction the add instruction to be instrumented
 */
void MSan::addHandler(Instruction_t *instruction){

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

    const string compilerRtPath = "/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compilerRT-build/lib/linux/";
    elfDeps->prependLibraryDepedencies(compilerRtPath + "libclang_rt.msan_cxx-x86_64.so");
    elfDeps->prependLibraryDepedencies(compilerRtPath + "libclang_rt.msan-x86_64.so");

    getFileIR()->assembleRegistry();
}

bool MSan::parseArgs(std::vector<std::string> step_args) {
    return true;
}

//
// Created by Franziska Mäckel on 03.04.22.
//

#include "msan.hpp"

using namespace IRDB_SDK;
using namespace std;

// constructor
MSan::MSan(FileIR_t *p_variantIR)
        :
        Transform_t(p_variantIR) // init Transform_t class for insertAssembly and getFileIR
{
    MSan::reserveMemoryForRegisters();
}

bool MSan::execute(IRDB_SDK::FileIR_t *fileIr)
{
    if (shadowRegisters[0] == 0){
        shadowRegisters[1] = 5;
    }

    Instruction_t* instruction = nullptr;
    auto functions = fileIr->getFunctions();
    for (auto const &function : functions){
        if(function->getName() == "main"){
            instruction = *(function->getInstructions().begin());
            cout << "Main found! First instruction: " << instruction->getDisassembly();
            break;
        }
    }
    std::string instrumentation = std::string() +
                                  "pushf\n"           // save eflags
                                  "push   rax\n"      // save rax
                                  "mov    al, %%1\n"  // load shadow
                                  "pop    rax\n"      // restore rax
                                  "popf\n";           // restore eflags
    vector<basic_string<char>> instrumentationParams {to_string(shadowRegisters[1])};
    const auto new_instr = ::insertAssemblyInstructionsAfter(fileIr, instruction, instrumentation, instrumentationParams);
    cout << "MSan step was executed. Look for:\n" << instrumentation;
    IRDB_SDK::registerToString()
    return true;
}

/**
 * Reserves memory for the shadowing of the 16 general purpose registers and initialises
 * the shadowRegisters pointer. Upon initialisation, all register shadows are undefined (0 = undefined).
 */
void MSan::reserveMemoryForRegisters(){
    MSan::shadowRegisters = std::vector<int64_t>(16,0);
}



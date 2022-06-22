//
// Created by Franziska Mäckel on 05.06.22.
//

#include "MemoryAccessInstrumentation.h"

using namespace IRDB_SDK;

/**
 * Inserts instrumentation to verify that a memory access does not use an uninitialised base or index register.
 *
 * Side effect: Since new instrumentation is inserted before the instruction pointed to by <code>instruction</code>,
 * the pointer will not point to the original instruction anymore afterwards. Therefore, a pointer to the original
 * instruction is returned.
 *
 * @param operand The operand that contains the memory access.
 * @param instruction The instruction that contains the operand with the memory access.
 * @return Returns a pointer to the original instruction.
 */
Instruction_t* MemoryAccessInstrumentation::instrumentMemRef(const std::shared_ptr<DecodedOperand_t> &operand,
                                                             Instruction_t *instruction,
                                                             std::unique_ptr<CapstoneService> &capstoneService,
                                                             FileIR_t *fileIr) {
    std::cout << "instrumentMemRef. Operand: " << operand->getString() << std::endl;
    IRDB_SDK::Instruction_t *originalInstruction = instruction;
    if(operand->hasBaseRegister()){
        auto baseReg = operand->getBaseRegister();
        auto baseRegWidth = capstoneService->getBaseRegWidth(instruction);

        std::string instrumentation = std::string() +
                                 Utils::getPushCallerSavedRegistersInstrumentation() +
                                 "mov rdi, %%1\n" +    // first argument
                                 "mov rsi, %%2\n" +    // second argument
                                 "call 0\n" +
                                 Utils::getPopCallerSavedRegistersInstrumentation();
        std::vector<std::__cxx11::basic_string<char>> instrumentationParams {std::__cxx11::to_string(baseReg), std::__cxx11::to_string(baseRegWidth)};
        const auto new_instr = IRDB_SDK::insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation, instrumentationParams);
        new_instr[12]->setTarget(RuntimeLib::checkRegIsInit);
        originalInstruction = new_instr[new_instr.size()-1];
    }
    if(operand->hasIndexRegister()){
        auto indexReg = operand->getIndexRegister();
        auto indexRegWidth = capstoneService->getIndexRegWidth(instruction);

        std::string instrumentation = std::string() +
                                 Utils::getPushCallerSavedRegistersInstrumentation() +
                                 "mov rdi, %%1\n" +    // first argument
                                 "mov rsi, %%2\n" +    // second argument
                                 "call 0\n" +
                                 Utils::getPopCallerSavedRegistersInstrumentation();
        std::vector<std::__cxx11::basic_string<char>> instrumentationParams {std::__cxx11::to_string(indexReg), std::__cxx11::to_string(indexRegWidth)};
        const auto new_instr = ::IRDB_SDK::insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation, instrumentationParams);
        new_instr[13]->setTarget(RuntimeLib::checkRegIsInit);
        originalInstruction = new_instr[new_instr.size()-1];
    }
    return originalInstruction;
}
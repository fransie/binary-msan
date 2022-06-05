//
// Created by Franziska Mäckel on 05.06.22.
//

#include "MovHandler.h"
#include "Utils.h"
#include "MemoryAccessHandler.h"

#include <memory>
#include <irdb-elfdep>

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
IRDB_SDK::Instruction_t* MemoryAccessHandler::instrumentMemRef(const std::shared_ptr<IRDB_SDK::DecodedOperand_t> &operand,
                                                               IRDB_SDK::Instruction_t *instruction,
                                                               std::unique_ptr<CapstoneService> &capstoneService,
                                                               IRDB_SDK::FileIR_t *fileIr) {
    std::cout << "instrumentMemRef. Operand: " << operand->getString() << std::endl;
    IRDB_SDK::Instruction_t *originalInstruction = instruction;
    if(operand->hasBaseRegister()){
        auto baseReg = operand->getBaseRegister();
        auto baseRegWidth = capstoneService->getBaseRegWidth(instruction);

        std::string instrumentation = std::string() +
                                      "pushf\n" +           // save eflags (necessary?)
                                 Utils::getPushCallerSavedRegistersInstrumentation() +
                                      "mov rdi, %%1\n" +    // first argument
                                 "mov rsi, %%2\n" +    // second argument
                                 "call 0\n" +
                                      Utils::getPopCallerSavedRegistersInstrumentation() +
                                      "popf\n";             // restore eflags
        std::vector<std::__cxx11::basic_string<char>> instrumentationParams {std::__cxx11::to_string(baseReg), std::__cxx11::to_string(baseRegWidth)};
        const auto new_instr = IRDB_SDK::insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation, instrumentationParams);
        new_instr[12]->setTarget(RuntimeLib::checkRegIsInit);
        originalInstruction = new_instr[new_instr.size()-1];
        std::cout << "instrumentMemRef base. Inserted the following base reg instrumentation: " << instrumentation << std::endl;
    }
    if(operand->hasIndexRegister()){
        auto indexReg = operand->getIndexRegister();
        auto indexRegWidth = capstoneService->getIndexRegWidth(instruction);

        std::string instrumentation = std::string() +
                                      "pushf\n" +           // save eflags (necessary?)
                                 Utils::getPushCallerSavedRegistersInstrumentation() +
                                      "mov rdi, %%1\n" +    // first argument
                                 "mov rsi, %%2\n" +    // second argument
                                 "call 0\n" +
                                      Utils::getPopCallerSavedRegistersInstrumentation() +
                                      "popf\n";             // restore eflags
        std::vector<std::__cxx11::basic_string<char>> instrumentationParams {std::__cxx11::to_string(indexReg), std::__cxx11::to_string(indexRegWidth)};
        const auto new_instr = ::IRDB_SDK::insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation, instrumentationParams);
        new_instr[12]->setTarget(RuntimeLib::checkRegIsInit);
        originalInstruction = new_instr[new_instr.size()-1];
        std::cout << "instrumentMemRef index. Inserted the following index reg instrumentation: " << instrumentation << std::endl;
    }
    return originalInstruction;
}
#include <irdb-elfdep>
#include <memory>
#include "DisassemblyService.h"
#include "MemoryAccessHandler.h"
#include "RuntimeLib.h"
#include "Utils.h"

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
IRDB_SDK::Instruction_t *MemoryAccessHandler::instrument(Instruction_t *instruction) {
    auto decodedInstruction = DecodedInstruction_t::factory(instruction);
    auto operands = decodedInstruction->getOperands();
    auto operand = operands[0];
    if (!operand->isMemory()) {
        operand = operands[1];
    }
    if (!operand->hasBaseRegister() && !operand->hasIndexRegister()) {
        return instruction;
    }
    std::cout << "MemoryAccessHandler. Operand: " << operand->getString() << std::endl;
    string instrumentation = Utils::getStateSavingInstrumentation();
    vector<basic_string<char>> instrumentationParams{4};
    auto regCount = 0;

    if (operand->hasBaseRegister()) {
        regCount++;
        auto baseReg = operand->getBaseRegister();
        auto baseRegWidth = disassemblyService->getBaseRegWidth(instruction);
        instrumentation = instrumentation +
                          "mov rdi, %%1\n" +    // first argument
                          "mov rsi, %%2\n" +    // second argument
                          "call 0\n";
        instrumentationParams[0] = Utils::toHex(baseReg);
        instrumentationParams[1] = Utils::toHex(baseRegWidth);
    }
    if (operand->hasIndexRegister()) {
        regCount++;
        auto indexReg = operand->getIndexRegister();
        auto indexRegWidth = disassemblyService->getIndexRegWidth(instruction);

        instrumentation = instrumentation +
                          "mov rdi, %%3\n" +    // first argument
                          "mov rsi, %%4\n" +    // second argument
                          "call 0\n";
        instrumentationParams[2] = Utils::toHex(indexReg);
        instrumentationParams[3] = Utils::toHex(indexRegWidth);
    }
    instrumentation = instrumentation + Utils::getStateRestoringInstrumentation();
    const auto new_instr = IRDB_SDK::insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation,
                                                                      instrumentationParams);
    auto calls = DisassemblyService::getCallInstructionPosition(new_instr);
    for (int index = 0; index < regCount ; index++) {
        new_instr[calls[index]]->setTarget(RuntimeLib::checkRegIsInit);
    }
    return new_instr.back();
}

bool MemoryAccessHandler::hasMemoryOperand(unique_ptr<DecodedInstruction_t> &instruction) {
    auto operands = instruction->getOperands();
    if (instruction->hasOperand(1)) {
        return operands[0]->isMemory() || operands[1]->isMemory();
    }
    if (instruction->hasOperand(0)) {
        return operands[0]->isMemory();
    }
    return false;
}

bool MemoryAccessHandler::isResponsibleFor(IRDB_SDK::Instruction_t *instruction) {
    auto decodedInstruction = IRDB_SDK::DecodedInstruction_t::factory(instruction);
    // Lea does not actually access memory.
    if (decodedInstruction->getMnemonic() == "lea") {
        return false;
    }
    return hasMemoryOperand(decodedInstruction);
}

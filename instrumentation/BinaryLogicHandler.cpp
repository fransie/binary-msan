#include <irdb-transform>
#include "BinaryLogicHandler.h"
#include "RuntimeLib.h"
#include "Utils.h"

using namespace IRDB_SDK;


Instruction_t* BinaryLogicHandler::instrument(IRDB_SDK::Instruction_t *instruction) {
    auto decodedInstruction = DecodedInstruction_t::factory(instruction);
    vector<shared_ptr<DecodedOperand_t>> operands = decodedInstruction->getOperands();
    if(operands[0]->isGeneralPurposeRegister()){
        if(operands[1]->isGeneralPurposeRegister()){
            return instrumentRegRegInstruction(instruction);
        } else if (operands[1]->isMemory()) {
            return instrumentRegMemInstruction(instruction);
        }
        // No instrumentation needed for immediate source operands since the resulting shadow value
        // of the destination register fully depends on itself.
    } else if (operands[0]->isMemory()) {
        if(operands[1]->isGeneralPurposeRegister()){
            return instrumentMemRegInstruction(instruction);
        }
        // No instrumentation needed for immediate source operands since the resulting shadow value
        // of the destination memory location fully depends on itself.
    }
    return instruction;
}

IRDB_SDK::Instruction_t* BinaryLogicHandler::instrumentRegRegInstruction(IRDB_SDK::Instruction_t *instruction) {
    auto operands = DecodedInstruction_t::factory(instruction)->getOperands();
    auto dest = operands[0]->getRegNumber();
    auto src = operands[1]->getRegNumber();
    auto destWidth = disassemblyService->getRegWidth(instruction, 0);
    auto srcWidth = disassemblyService->getRegWidth(instruction, 1);
    string instrumentation = string() +
            Utils::getStateSavingInstrumentation() +
                             "mov rdi, %%1\n" +    // dest
                             "mov rsi, %%2\n" +    // destWidth
                             "mov rdx, %%3\n" +    // src
                             "mov rcx, %%4\n" +    // srcWidth
                             "call 0\n" +
            Utils::getStateRestoringInstrumentation();
    vector<basic_string<char>> instrumentationParams {to_string((int)dest), to_string(destWidth), to_string((int)src), to_string(srcWidth)};
    const auto new_instr = insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation, instrumentationParams);
    auto calls = DisassemblyService::getCallInstructionPosition(new_instr);
    new_instr[calls[0]]->setTarget(RuntimeLib::propagateRegOrRegShadow);
    return new_instr.back();
}

IRDB_SDK::Instruction_t* BinaryLogicHandler::instrumentMemRegInstruction(IRDB_SDK::Instruction_t *instruction) {
    auto operands = DecodedInstruction_t::factory(instruction)->getOperands();
    int reg = operands[1]->getRegNumber();
    int width = disassemblyService->getRegWidth(instruction, 1);
    auto memory = disassemblyService->getMemoryOperandDisassembly(instruction);
    string instrumentation = string() +
                             Utils::getStateSavingInstrumentation() +
                             "lea rdi, %%1\n" +    // mem
                             "mov rsi, %%2\n" +    // reg
                             "mov rdx, %%3\n" +    // width
                             "call 0\n" +
                             Utils::getStateRestoringInstrumentation();
    vector<basic_string<char>> instrumentationParams {memory, to_string(reg), to_string(width)};
    const auto new_instr = IRDB_SDK::insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation, instrumentationParams);
    auto calls = DisassemblyService::getCallInstructionPosition(new_instr);
    new_instr[calls[0]]->setTarget(RuntimeLib::propagateMemOrRegShadow);
    return new_instr.back();

}

IRDB_SDK::Instruction_t* BinaryLogicHandler::instrumentRegMemInstruction(IRDB_SDK::Instruction_t *instruction) {
    auto operands = DecodedInstruction_t::factory(instruction)->getOperands();
    int reg = operands[0]->getRegNumber();
    int width = disassemblyService->getRegWidth(instruction, 0);
    auto memory = disassemblyService->getMemoryOperandDisassembly(instruction);
    string instrumentation = string() +
                             Utils::getStateSavingInstrumentation() +
                             "lea rdi, %%1\n" +    // mem
                             "mov rsi, %%2\n" +    // reg
                             "mov rdx, %%3\n" +    // width
                             "call 0\n" +
                             Utils::getStateRestoringInstrumentation();
    vector<basic_string<char>> instrumentationParams {memory, to_string(reg), to_string(width)};
    const auto new_instr = IRDB_SDK::insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation, instrumentationParams);
    auto calls = DisassemblyService::getCallInstructionPosition(new_instr);
    new_instr[calls[0]]->setTarget(RuntimeLib::propagateRegOrMemShadow);
    return new_instr.back();
}

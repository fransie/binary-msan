#include <irdb-transform>
#include "BinaryArithmeticHandler.h"
#include "RuntimeLib.h"
#include "Utils.h"

using namespace IRDB_SDK;


Instruction_t *BinaryArithmeticHandler::instrument(IRDB_SDK::Instruction_t *instruction) {
    std::cout << "BinaryArithmeticHandler: Instruction " << instruction->getDisassembly() << std::endl;
    auto decodedInstruction = DecodedInstruction_t::factory(instruction);
    vector<shared_ptr<DecodedOperand_t>> operands = decodedInstruction->getOperands();
    if (operands[0]->isGeneralPurposeRegister()) {
        if (operands[1]->isGeneralPurposeRegister()) {
            return instrumentRegRegInstruction(instruction);
        } else if (operands[1]->isMemory()) {
            return instrumentRegMemInstruction(instruction);
        } else if (operands[1]->isConstant()) {
            return instrumentRegImm(instruction);
        }
    } else if (operands[0]->isMemory()) {
        if (operands[1]->isGeneralPurposeRegister()) {
            return instrumentMemRegInstruction(instruction);
        } else if (operands[1]->isConstant()) {
            return instrumentMemImmInstruction(instruction);
        }
    }
    return instruction;
}

IRDB_SDK::Instruction_t *BinaryArithmeticHandler::instrumentRegRegInstruction(IRDB_SDK::Instruction_t *instruction) {
    auto operands = DecodedInstruction_t::factory(instruction)->getOperands();
    auto dest = operands[0]->getRegNumber();
    auto src = operands[1]->getRegNumber();
    auto destWidth = disassemblyService->getRegWidth(instruction, 0);
    auto srcWidth = disassemblyService->getRegWidth(instruction, 1);
    string instrumentation =
            Utils::getStateSavingInstrumentation() +
            "mov rdi, %%1\n" +      // reg1
            "mov rsi, %%2\n" +      // reg1Width
            "mov rdx, %%3\n" +      // reg2
            "mov rcx, %%4\n" +      // reg2Width
            "call 0\n" +            // isRegOrRegFullyDefined
            "mov dil, al\n" +       // setToUnpoisoned
            "mov rsi, %%1\n" +      // reg
            "mov rdx, %%2\n" +      // regWidth
            "call 0\n" +            // setRegShadow
            Utils::getStateRestoringInstrumentation();
    vector<basic_string<char>> instrumentationParams{Utils::toHex( dest), Utils::toHex(destWidth), Utils::toHex(src),
                                                     Utils::toHex(srcWidth)};
    const auto new_instr = insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation,
                                                            instrumentationParams);
    auto calls = DisassemblyService::getCallInstructionPosition(new_instr);
    new_instr[calls[0]]->setTarget(RuntimeLib::isRegOrRegFullyDefined);
    new_instr[calls[1]]->setTarget(RuntimeLib::setRegShadow);
    return new_instr.back();
}

IRDB_SDK::Instruction_t *BinaryArithmeticHandler::instrumentMemRegInstruction(IRDB_SDK::Instruction_t *instruction) {
    auto operands = DecodedInstruction_t::factory(instruction)->getOperands();
    auto reg = operands[1]->getRegNumber();
    auto width = disassemblyService->getRegWidth(instruction, 1);
    auto memory = disassemblyService->getMemoryOperandDisassembly(instruction);
    string instrumentation =
            Utils::getStateSavingInstrumentation() +
            "lea rdi, %%1\n" +      // mem
            "mov rsi, %%2\n" +      // reg
            "mov rdx, %%3\n" +      // width
            "call 0\n" +            // isRegOrMemFullyDefined
            "lea rdi, %%1\n" +      // mem
            "mov sil, al\n" +       // setToUnpoisoned
            "mov rdx, %%3\n" +      // size
            "call 0\n" +            // setMemShadow
            Utils::getStateRestoringInstrumentation();
    vector<basic_string<char>> instrumentationParams{memory, Utils::toHex(reg), Utils::toHex(width)};
    const auto new_instr = IRDB_SDK::insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation,
                                                                      instrumentationParams);
    auto calls = DisassemblyService::getCallInstructionPosition(new_instr);
    new_instr[calls[0]]->setTarget(RuntimeLib::isRegOrMemFullyDefined);
    new_instr[calls[1]]->setTarget(RuntimeLib::setMemShadow);
    return new_instr.back();
}

IRDB_SDK::Instruction_t *BinaryArithmeticHandler::instrumentRegMemInstruction(IRDB_SDK::Instruction_t *instruction) {
    auto operands = DecodedInstruction_t::factory(instruction)->getOperands();
    auto reg = operands[0]->getRegNumber();
    auto width = disassemblyService->getRegWidth(instruction, 0);
    auto memory = disassemblyService->getMemoryOperandDisassembly(instruction);
    string instrumentation =
            Utils::getStateSavingInstrumentation() +
            "lea rdi, %%1\n" +      // mem
            "mov rsi, %%2\n" +      // reg
            "mov rdx, %%3\n" +      // width
            "call 0\n" +            // isRegOrMemFullyDefined
            "mov dil, al\n" +       // setToUnpoisoned
            "mov rsi, %%2\n" +      // reg
            "mov rdx, %%3\n" +      // width
            "call 0\n" +            // setRegShadow
            Utils::getStateRestoringInstrumentation();
    vector<basic_string<char>> instrumentationParams{memory, Utils::toHex(reg), Utils::toHex(width)};
    const auto new_instr = IRDB_SDK::insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation,
                                                                      instrumentationParams);
    auto calls = DisassemblyService::getCallInstructionPosition(new_instr);
    new_instr[calls[0]]->setTarget(RuntimeLib::isRegOrMemFullyDefined);
    new_instr[calls[1]]->setTarget(RuntimeLib::setRegShadow);
    return new_instr.back();
}

IRDB_SDK::Instruction_t *BinaryArithmeticHandler::instrumentRegImm(IRDB_SDK::Instruction_t *instruction) {
    auto operands = DecodedInstruction_t::factory(instruction)->getOperands();
    auto dest = operands[0]->getRegNumber();
    auto destWidth = disassemblyService->getRegWidth(instruction, 0);
    string instrumentation =
            Utils::getStateSavingInstrumentation() +
            "mov rdi, %%1\n" +      // reg
            "mov rsi, %%2\n" +      // width
            "call 0\n" +            // isRegFullyDefined
            "mov dil, al\n" +       // setToUnpoisoned
            "mov rsi, %%1\n" +      // reg
            "mov rdx, %%2\n" +      // regWidth
            "call 0\n" +            // setRegShadow
            Utils::getStateRestoringInstrumentation();
    vector<basic_string<char>> instrumentationParams{Utils::toHex((int) dest), Utils::toHex(destWidth)};
    const auto new_instr = insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation,
                                                            instrumentationParams);
    auto calls = DisassemblyService::getCallInstructionPosition(new_instr);
    new_instr[calls[0]]->setTarget(RuntimeLib::isRegFullyDefined);
    new_instr[calls[1]]->setTarget(RuntimeLib::setRegShadow);
    return new_instr.back();
}

IRDB_SDK::Instruction_t *BinaryArithmeticHandler::instrumentMemImmInstruction(IRDB_SDK::Instruction_t *instruction) {
    auto operands = DecodedInstruction_t::factory(instruction)->getOperands();
    auto width = operands[0]->getArgumentSizeInBits();
    auto memory = disassemblyService->getMemoryOperandDisassembly(instruction);
    string instrumentation =
            Utils::getStateSavingInstrumentation() +
            "lea rdi, %%1\n" +      // mem
            "mov rsi, %%2\n" +      // size
            "call 0\n" +            // isMemFullyDefined
            "lea rdi, %%1\n" +      // mem
            "mov sil, al\n" +       // setToUnpoisoned
            "mov rdx, %%2\n" +      // size
            "call 0\n" +            // setMemShadow
            Utils::getStateRestoringInstrumentation();
    vector<basic_string<char>> instrumentationParams{memory, Utils::toHex(width)};
    const auto new_instr = IRDB_SDK::insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation,
                                                                      instrumentationParams);
    auto calls = DisassemblyService::getCallInstructionPosition(new_instr);
    new_instr[calls[0]]->setTarget(RuntimeLib::isMemFullyDefined);
    new_instr[calls[1]]->setTarget(RuntimeLib::setMemShadow);
    return new_instr.back();
}

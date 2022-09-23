#include <irdb-transform>
#include "../common/Width.h"
#include "MovHandler.h"
#include "RuntimeLib.h"
#include "Utils.h"
#include "MemoryAccessHandler.h"

using namespace IRDB_SDK;
using namespace std;

/**
 * Takes a mov instruction and inserts instrumentation before it so that the shadow is handled correctly.
 */
IRDB_SDK::Instruction_t *MovHandler::instrument(Instruction_t *instruction) {
    std::cout << "MovHandler: Instruction " << instruction->getDisassembly() << std::endl;
    auto decodedInstruction = DecodedInstruction_t::factory(instruction);
    vector<shared_ptr<DecodedOperand_t>> operands = decodedInstruction->getOperands();
    if (operands[0]->isGeneralPurposeRegister()) {
        if (operands[1]->isGeneralPurposeRegister()) {
            return instrumentRegToRegMove(instruction);
        } else if (operands[1]->isConstant()) {
            return instrumentImmToRegMove(instruction);
        } else if (operands[1]->isMemory()) {
            return instrumentMemToRegMove(instruction);
        }
    } else if (operands[0]->isMemory()) {
        if (operands[1]->isGeneralPurposeRegister()) {
            return instrumentRegToMemMove(instruction);
        } else if (operands[1]->isConstant()) {
            return instrumentImmToMemMove(instruction);
        }
    }
    return instruction;
}

/**
 * Adds instrumentation before <code>instruction</code> that unpoisons the shadow of the destination memory operand according
 * to its width.
 * @param instruction mov [mem], immediate instruction
 */
IRDB_SDK::Instruction_t *MovHandler::instrumentImmToMemMove(IRDB_SDK::Instruction_t *instruction) {
    auto operands = DecodedInstruction_t::factory(instruction)->getOperands();
    auto dest = disassemblyService->getMemoryOperandDisassembly(instruction);
    auto destWidth = operands[0]->getArgumentSizeInBytes();
    string instrumentation = string() +
                             Utils::getStateSavingInstrumentation() +
                             "lea rdi, %%1\n" +    // first argument
                             "mov rsi, %%2\n" +    // second argument
                             "call 0\n" +
                             Utils::getStateRestoringInstrumentation();
    vector<basic_string<char>> instrumentationParams{dest, to_string(Utils::toHex(destWidth))};
    const auto new_instr = IRDB_SDK::insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation,
                                                                      instrumentationParams);
    auto calls = DisassemblyService::getCallInstructionPosition(new_instr);
    new_instr[calls[0]]->setTarget(RuntimeLib::msan_unpoison);
    return new_instr.back();
}

/**
 * Adds instrumentation before <code>instruction</code> that unpoisons the shadow of the destination register according
 * to its width. Exception: If it is a double-word move, then also the higher four bytes are unpoisoned.
 * @param instruction mov reg, immediate instruction
 */
IRDB_SDK::Instruction_t *MovHandler::instrumentImmToRegMove(Instruction_t *instruction) {
    auto operands = DecodedInstruction_t::factory(instruction)->getOperands();
    auto dest = operands[0]->getRegNumber();
    auto width = disassemblyService->getRegWidth(instruction, 0);
    string instrumentation = string() +
                             Utils::getStateSavingInstrumentation() +
                             "mov dil, 1\n" +      // isInited
                             "mov rsi, %%1\n" +    // reg
                             "mov rdx, %%2\n" +    // regWidth
                             "call 0\n";
    if (width == Utils::toHex(DOUBLE_WORD)) {
        instrumentation = instrumentation +
                          "mov rdi, %%1\n" +    // reg
                          "call 0\n";
    }
    instrumentation += Utils::getStateRestoringInstrumentation();
    vector<basic_string<char>> instrumentationParams{to_string((int) dest), to_string(width)};
    const auto new_instr = IRDB_SDK::insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation,
                                                                      instrumentationParams);
    auto calls = DisassemblyService::getCallInstructionPosition(new_instr);
    new_instr[calls[0]]->setTarget(RuntimeLib::setRegShadow);
    if (width == Utils::toHex(DOUBLE_WORD)) {
        new_instr[calls[1]]->setTarget(RuntimeLib::unpoisonUpper4Bytes);
    }
    return new_instr.back();
}

/**
 * Adds instrumentation before <code>instruction</code> that propagates the shadow of the source memory operand
 * to the destination register according to their width. Exception: If it is a double-word move, then the
 * higher four bytes are unpoisoned.
 * @param instruction mov reg, [mem] instruction
 */
IRDB_SDK::Instruction_t *MovHandler::instrumentMemToRegMove(Instruction_t *instruction) {
    auto operands = DecodedInstruction_t::factory(instruction)->getOperands();
    auto dest = operands[0]->getRegNumber();

    auto memoryDisassembly = disassemblyService->getMemoryOperandDisassembly(instruction);
    auto width = disassemblyService->getRegWidth(instruction, 0);
    // Higher four bytes are zeroed for double word moves.
    string instrumentation = string() +
                             Utils::getStateSavingInstrumentation() +
                             "lea rdi, %%1\n" +    // memAddr
                             "mov rsi, %%2\n" +    // reg
                             "mov rdx, %%3\n" +    // regWidth
                             "call 0\n";
    if (width == Utils::toHex(DOUBLE_WORD)) {
        instrumentation = instrumentation +
                          "mov rdi, %%2\n" +    // reg
                          "call 0\n";
    }
    instrumentation += Utils::getStateRestoringInstrumentation();
    vector<basic_string<char>> instrumentationParams{memoryDisassembly, to_string(dest), to_string(width)};
    const auto new_instr = ::IRDB_SDK::insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation,
                                                                        instrumentationParams);
    auto calls = DisassemblyService::getCallInstructionPosition(new_instr);
    new_instr[calls[0]]->setTarget(RuntimeLib::memToRegShadowCopy);
    if (width == Utils::toHex(DOUBLE_WORD)) {
        new_instr[calls[1]]->setTarget(RuntimeLib::unpoisonUpper4Bytes);
    }
    return new_instr.back();
}


/** Adds instrumentation before <code>instruction</code> that propagates the shadow of the source register
*  to the destination memory operand according to their width.
* @param instruction mov [mem], reg instruction
*/
IRDB_SDK::Instruction_t *MovHandler::instrumentRegToMemMove(IRDB_SDK::Instruction_t *instruction) {
    auto operands = DecodedInstruction_t::factory(instruction)->getOperands();

    auto src = operands[1]->getRegNumber();
    auto width = disassemblyService->getRegWidth(instruction, 1);
    auto memoryDisassembly = disassemblyService->getMemoryOperandDisassembly(instruction);
    string instrumentation = string() +
                             Utils::getStateSavingInstrumentation() +
                             "lea rdi, %%1\n" +    // memAddr
                             "mov rsi, %%2\n" +    // reg
                             "mov rdx, %%3\n" +    // regWidth
                             "call 0\n" +
                             Utils::getStateRestoringInstrumentation();
    vector<basic_string<char>> instrumentationParams{memoryDisassembly, to_string(src), to_string(width)};
    const auto new_instr = ::IRDB_SDK::insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation,
                                                                        instrumentationParams);
    auto calls = DisassemblyService::getCallInstructionPosition(new_instr);
    new_instr[calls[0]]->setTarget(RuntimeLib::regToMemShadowCopy);
    return new_instr.back();
}

/**
 * Takes a move instruction from one general purpose registers to another and inserts shadow propagating
 * instrumentation before the instruction. If it is a double-word move, then the higher four bytes are unpoisoned.
 * @param instruction a pointer to the move instruction.
 */
IRDB_SDK::Instruction_t *MovHandler::instrumentRegToRegMove(Instruction_t *instruction) {
    const auto operands = DecodedInstruction_t::factory(instruction)->getOperands();
    const auto dest = operands[0]->getRegNumber();
    const auto source = operands[1]->getRegNumber();

    auto destWidth = disassemblyService->getRegWidth(instruction, 0);
    auto srcWidth = disassemblyService->getRegWidth(instruction, 1);
    string instrumentation = string() +
                             Utils::getStateSavingInstrumentation() +
                             "mov rdi, %%1\n" +    // dest
                             "mov rsi, %%2\n" +    // destWidth
                             "mov rdx, %%3\n"      // src
                             "mov rcx, %%4\n"      // srcWidth
                             "call 0\n";
    if (destWidth == Utils::toHex(DOUBLE_WORD)) {
        instrumentation = instrumentation +
                          "mov rdi, %%1\n" +    // reg
                          "call 0\n";
    }
    instrumentation += Utils::getStateRestoringInstrumentation();
    vector<basic_string<char>> instrumentationParams{to_string(dest), to_string(destWidth), to_string(source),
                                                     to_string(srcWidth)};
    const auto new_instr = ::IRDB_SDK::insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation,
                                                                        instrumentationParams);
    auto calls = DisassemblyService::getCallInstructionPosition(new_instr);
    new_instr[calls[0]]->setTarget(RuntimeLib::regToRegShadowCopy);
    if (destWidth == Utils::toHex(DOUBLE_WORD)) {
        new_instr[calls[1]]->setTarget(RuntimeLib::unpoisonUpper4Bytes);
    }
    return new_instr.back();
}
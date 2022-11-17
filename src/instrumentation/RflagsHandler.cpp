#include <irdb-transform>
#include "RflagsHandler.h"
#include "RuntimeLib.h"
#include "Utils.h"

using namespace IRDB_SDK;
using namespace std;

IRDB_SDK::Instruction_t *RflagsHandler::instrument(IRDB_SDK::Instruction_t *instruction) {
    std::cout << "RflagsHandler: Instruction " << instruction->getDisassembly() << std::endl;
    auto decodedInstruction = DecodedInstruction_t::factory(instruction);
    vector<shared_ptr<DecodedOperand_t>> operands = decodedInstruction->getOperands();
    if (operands[0]->isGeneralPurposeRegister()) {
        if (operands[1]->isGeneralPurposeRegister()) {
            if (operands[0]->getRegNumber() == operands[1]->getRegNumber()) {
                // test regX, regX
                return propagateRegShadowToRflags(instruction);
            } else {
                // test regX, regY
                return propagateRegOrRegShadowToRflags(instruction);
            }
        } else if (operands[1]->isConstant()) {
            // reg and immediate
            return propagateRegShadowToRflags(instruction);
        } else if (operands[1]->isMemory()) {
            // reg and mem
            return propagateRegOrMemShadowToRflags(instruction);
        }
    } else if (operands[0]->isMemory()) {
        if (operands[1]->isGeneralPurposeRegister()) {
            // mem and reg
            return propagateRegOrMemShadowToRflags(instruction);
        } else if (operands[1]->isConstant()) {
            // mem and immediate
            return propagateMemShadowToRflags(instruction);
        }
    }
    return instruction;
}

/**
 * Takes an instruction that affects the RFLAGS register and sets the shadow of the RFLAGS shadow bit
 * according to the register used in the instruction. The definedness of RFLAGS depends only
 * on the first operand, e.g. as in <code>test eax, 0</code> or <code>test eax, eax</code>.
 *
 * shadow(Rflags) = shadow(destReg)
 *
 * @param instruction Instruction that affects RFLAGS register.
 */
IRDB_SDK::Instruction_t *RflagsHandler::propagateRegShadowToRflags(IRDB_SDK::Instruction_t *instruction) {
    auto operands = DecodedInstruction_t::factory(instruction)->getOperands();
    auto dest = operands[0]->getRegNumber();
    auto width = disassemblyService->getRegWidth(instruction, 0);
    string instrumentation = string() +
                             Utils::getStateSavingInstrumentation() +
                             "mov rdi, %%1\n" +
                             "mov rsi, %%2\n" +
                             "call 0\n" +
                             "mov dil, al\n" +
                             "call 0\n" +
                             Utils::getStateRestoringInstrumentation();
    vector<basic_string<char>> instrumentationParams{Utils::toHex(dest), Utils::toHex(width)};
    const auto new_instr = IRDB_SDK::insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation,
                                                                      instrumentationParams);
    auto calls = DisassemblyService::getCallInstructionPosition(new_instr);
    new_instr[calls[0]]->setTarget(RuntimeLib::isRegFullyDefined);
    new_instr[calls[1]]->setTarget(RuntimeLib::setRflags);
    return new_instr.back();
}

/**
 * Takes an instruction that affects the RFLAGS register and sets the shadow of the RFLAGS shadow bit
 * according to the memory operand used in the instruction. The definedness of RFLAGS depends only
 * on the first operand, e.g. as in <code>test [rbp - 4], 0</code>.
 *
 * shadow(Rflags) = shadow(memory)
 *
 * @param instruction Instruction that affects RFLAGS register.
 */
IRDB_SDK::Instruction_t *RflagsHandler::propagateMemShadowToRflags(IRDB_SDK::Instruction_t *instruction) {
    auto operands = DecodedInstruction_t::factory(instruction)->getOperands();
    auto dest = disassemblyService->getMemoryOperandDisassembly(instruction);
    auto destWidth = operands[0]->getArgumentSizeInBytes();
    string instrumentation = string() +
                             Utils::getStateSavingInstrumentation() +
                             "lea rdi, %%1\n" +
                             "mov rsi, %%2\n" +
                             "call 0\n" +
                             "mov dil, al\n" +
                             "call 0\n" +
                             Utils::getStateRestoringInstrumentation();
    vector<basic_string<char>> instrumentationParams{dest, Utils::toHex(destWidth)};
    const auto new_instr = IRDB_SDK::insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation,
                                                                      instrumentationParams);
    auto calls = DisassemblyService::getCallInstructionPosition(new_instr);
    new_instr[calls[0]]->setTarget(RuntimeLib::isMemFullyDefined);
    new_instr[calls[1]]->setTarget(RuntimeLib::setRflags);
    return new_instr.back();
}

/**
 * Takes an instruction that affects the RFLAGS register and sets the shadow of the RFLAGS shadow bit
 * according to the registers used in the instruction. The definedness of RFLAGS depends on the bitwise OR
 * of the shadow states of both registers, e.g. as in <code>cmp rax, rbx</code>.
 *
 * shadow(Rflags) = shadow(destReg) | shadow(srcReg)
 *
 * @param instruction Instruction that affects RFLAGS register.
 */
IRDB_SDK::Instruction_t *RflagsHandler::propagateRegOrRegShadowToRflags(IRDB_SDK::Instruction_t *instruction) {
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
                             "mov dil, al\n" +
                             "call 0\n" +
                             Utils::getStateRestoringInstrumentation();
    vector<basic_string<char>> instrumentationParams{Utils::toHex(dest), Utils::toHex(destWidth), Utils::toHex(src),
                                                     Utils::toHex(srcWidth)};
    const auto new_instr = IRDB_SDK::insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation,
                                                                      instrumentationParams);
    auto calls = DisassemblyService::getCallInstructionPosition(new_instr);
    new_instr[calls[0]]->setTarget(RuntimeLib::isRegOrRegFullyDefined);
    new_instr[calls[1]]->setTarget(RuntimeLib::setRflags);
    return new_instr.back();
}

/**
 * Takes an instruction that affects the RFLAGS register and sets the shadow of the RFLAGS shadow bit
 * according to the register and memory operand used in the instruction. The definedness of RFLAGS depends on the bitwise OR
 * of the shadow states of both operands, e.g. as in <code>cmp rax, [rbp - 4]</code>.
 *
 * shadow(Rflags) = shadow(dest) | shadow(src)
 *
 * @param instruction Instruction that affects RFLAGS register.
 */
IRDB_SDK::Instruction_t *RflagsHandler::propagateRegOrMemShadowToRflags(IRDB_SDK::Instruction_t *instruction) {
    auto operands = DecodedInstruction_t::factory(instruction)->getOperands();
    uint32_t reg;
    uint32_t width;
    if (operands[0]->isGeneralPurposeRegister()) {
        reg = operands[0]->getRegNumber();
        width = disassemblyService->getRegWidth(instruction, 0);
    } else {
        reg = operands[1]->getRegNumber();
        width = disassemblyService->getRegWidth(instruction, 1);
    }
    auto memory = disassemblyService->getMemoryOperandDisassembly(instruction);
    string instrumentation = string() +
                             Utils::getStateSavingInstrumentation() +
                             "lea rdi, %%1\n" +    // mem
                             "mov rsi, %%2\n" +    // reg
                             "mov rdx, %%3\n" +    // width
                             "call 0\n" +
                             "mov dil, al\n" +
                             "call 0\n" +
                             Utils::getStateRestoringInstrumentation();
    vector<basic_string<char>> instrumentationParams{memory, Utils::toHex(reg), Utils::toHex(width)};
    const auto new_instr = IRDB_SDK::insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation,
                                                                      instrumentationParams);
    auto calls = DisassemblyService::getCallInstructionPosition(new_instr);
    new_instr[calls[0]]->setTarget(RuntimeLib::isRegOrMemFullyDefined);
    new_instr[calls[1]]->setTarget(RuntimeLib::setRflags);
    return new_instr.back();
}
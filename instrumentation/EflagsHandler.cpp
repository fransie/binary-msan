#include <irdb-transform>
#include "EflagsHandler.h"
#include "RuntimeLib.h"
#include "Utils.h"

using namespace IRDB_SDK;
using namespace std;

void EflagsHandler::instrument(IRDB_SDK::Instruction_t *instruction) {
    auto decodedInstruction = DecodedInstruction_t::factory(instruction);
    vector<shared_ptr<DecodedOperand_t>> operands = decodedInstruction->getOperands();
    if(operands[0]->isGeneralPurposeRegister()){
        if(operands[1]->isGeneralPurposeRegister()){
            if(operands[0]->getRegNumber() == operands[1]->getRegNumber()){
                // test regX, regX
                propagateRegShadowToEflags(instruction);
            } else {
                // test regX, regY
                propagateRegOrRegShadowToEflags(instruction);
            }
        } else if (operands[1]->isConstant()){
            // reg and immediate
            propagateRegShadowToEflags(instruction);
        } else if (operands[1]->isMemory()) {
            // reg and mem
            propagateRegOrMemShadowToEflags(instruction);
        }
    } else if (operands[0]->isMemory()) {
        if(operands[1]->isGeneralPurposeRegister()){
            // mem and reg
            propagateRegOrMemShadowToEflags(instruction);
        } else if (operands[1]->isConstant()){
            // mem and immediate
            propagateMemShadowToEflags(instruction);
        }
    }
}

const std::vector<std::string> &EflagsHandler::getAssociatedInstructions() {
    return associatedInstructions;
}

EflagsHandler::EflagsHandler(IRDB_SDK::FileIR_t *fileIr) : fileIr(fileIr){
    capstone = make_unique<DisassemblyService>();
}

/**
 * Takes an instruction that affects the EFLAGS register and sets the shadow of the EFLAGS shadow bit
 * according to the register used in the instruction. The definedness of EFLAGS depends only
 * on the first operand, e.g. as in <code>test eax, 0</code> or <code>test eax, eax</code>.
 *
 * shadow(Eflags) = shadow(destReg)
 *
 * @param instruction Instruction that affects EFLAGS register.
 */
void EflagsHandler::propagateRegShadowToEflags(IRDB_SDK::Instruction_t *instruction) {
    auto operands = DecodedInstruction_t::factory(instruction)->getOperands();
    auto dest = operands[0]->getRegNumber();
    auto width = capstone->getRegWidth(instruction, 0);
    string instrumentation = string() +
            Utils::getStateSavingInstrumentation() +
                             "mov rdi, %%1\n" +
                             "mov rsi, %%2\n" +
                             "call 0\n" +
                             "mov dil, al\n" +
                             "call 0\n" +
            Utils::getStateRestoringInstrumentation();
    vector<basic_string<char>> instrumentationParams {to_string((int)dest), to_string(width)};
    const auto new_instr = IRDB_SDK::insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation, instrumentationParams);
    auto calls = DisassemblyService::getCallInstructionPosition(new_instr);
    new_instr[calls[0]]->setTarget(RuntimeLib::isRegFullyDefined);
    new_instr[calls[1]]->setTarget(RuntimeLib::setEflags);
}

/**
 * Takes an instruction that affects the EFLAGS register and sets the shadow of the EFLAGS shadow bit
 * according to the memory operand used in the instruction. The definedness of EFLAGS depends only
 * on the first operand, e.g. as in <code>test [rbp - 4], 0</code>.
 *
 * shadow(Eflags) = shadow(memory)
 *
 * @param instruction Instruction that affects EFLAGS register.
 */
void EflagsHandler::propagateMemShadowToEflags(IRDB_SDK::Instruction_t *instruction) {
    auto operands = DecodedInstruction_t::factory(instruction)->getOperands();
    auto dest = capstone->getMemoryOperandDisassembly(instruction);
    auto destWidth = operands[0]->getArgumentSizeInBytes();
    string instrumentation = string() +
            Utils::getStateSavingInstrumentation() +
                             "lea rdi, %%1\n" +
                             "mov rsi, %%2\n" +
                             "call 0\n" +
                             "mov dil, al\n" +
                             "call 0\n" +
            Utils::getStateRestoringInstrumentation();
    vector<basic_string<char>> instrumentationParams {dest, to_string(Utils::toHex(destWidth))};
    const auto new_instr = IRDB_SDK::insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation, instrumentationParams);
    auto calls = DisassemblyService::getCallInstructionPosition(new_instr);
    new_instr[calls[0]]->setTarget(RuntimeLib::isMemFullyDefined);
    new_instr[calls[1]]->setTarget(RuntimeLib::setEflags);
}

/**
 * Takes an instruction that affects the EFLAGS register and sets the shadow of the EFLAGS shadow bit
 * according to the registers used in the instruction. The definedness of EFLAGS depends on the bitwise OR
 * of the shadow states of both registers, e.g. as in <code>cmp rax, rbx</code>.
 *
 * shadow(Eflags) = shadow(destReg) | shadow(srcReg)
 *
 * @param instruction Instruction that affects EFLAGS register.
 */
void EflagsHandler::propagateRegOrRegShadowToEflags(IRDB_SDK::Instruction_t *instruction) {
    auto operands = DecodedInstruction_t::factory(instruction)->getOperands();
    auto dest = operands[0]->getRegNumber();
    auto src = operands[1]->getRegNumber();
    auto destWidth = capstone->getRegWidth(instruction, 0);
    auto srcWidth = capstone->getRegWidth(instruction, 1);
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
    vector<basic_string<char>> instrumentationParams {to_string((int)dest), to_string(destWidth), to_string((int)src), to_string(srcWidth)};
    const auto new_instr = IRDB_SDK::insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation, instrumentationParams);
    auto calls = DisassemblyService::getCallInstructionPosition(new_instr);
    new_instr[calls[0]]->setTarget(RuntimeLib::isRegOrRegFullyDefined);
    new_instr[calls[1]]->setTarget(RuntimeLib::setEflags);
}

/**
 * Takes an instruction that affects the EFLAGS register and sets the shadow of the EFLAGS shadow bit
 * according to the register and memory operand used in the instruction. The definedness of EFLAGS depends on the bitwise OR
 * of the shadow states of both operands, e.g. as in <code>cmp rax, [rbp - 4]</code>.
 *
 * shadow(Eflags) = shadow(dest) | shadow(src)
 *
 * @param instruction Instruction that affects EFLAGS register.
 */
void EflagsHandler::propagateRegOrMemShadowToEflags(IRDB_SDK::Instruction_t *instruction) {
    auto operands = DecodedInstruction_t::factory(instruction)->getOperands();
    int reg;
    int width;
    if(operands[0]->isGeneralPurposeRegister()){
        reg = operands[0]->getRegNumber();
        width = capstone->getRegWidth(instruction, 0);
    } else{
        reg = operands[1]->getRegNumber();
        width = capstone->getRegWidth(instruction, 1);
    }
    auto memory = capstone->getMemoryOperandDisassembly(instruction);
    string instrumentation = string() +
            Utils::getStateSavingInstrumentation() +
                             "lea rdi, %%1\n" +    // mem
                             "mov rsi, %%2\n" +    // reg
                             "mov rdx, %%3\n" +    // width
                             "call 0\n" +
                             "mov dil, al\n" +
                             "call 0\n" +
            Utils::getStateRestoringInstrumentation();
    vector<basic_string<char>> instrumentationParams {memory, to_string(reg), to_string(width)};
    const auto new_instr = IRDB_SDK::insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation, instrumentationParams);
    auto calls = DisassemblyService::getCallInstructionPosition(new_instr);
    new_instr[calls[0]]->setTarget(RuntimeLib::isRegOrMemFullyDefined);
    new_instr[calls[1]]->setTarget(RuntimeLib::setEflags);
}
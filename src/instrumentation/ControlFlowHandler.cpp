#include <algorithm>
#include "ControlFlowHandler.h"
#include "../common/RegisterNumbering.h"
#include "../common/Width.h"
#include "RuntimeLib.h"
#include "Utils.h"

using namespace IRDB_SDK;
using namespace std;

IRDB_SDK::Instruction_t *ControlFlowHandler::instrument(Instruction_t *instruction) {
    cout << "ControlFlowHandler. Instruction: " << instruction->getDisassembly() << " at "
         << instruction->getAddress()->getVirtualOffset() << endl;
    auto decodedInstr = DecodedInstruction_t::factory(instruction);
    if (std::find(eflagsJumps.begin(), eflagsJumps.end(), decodedInstr->getMnemonic()) != eflagsJumps.end()) {
        instruction = checkRflags(instruction);
    } else if (std::find(cxJumps.begin(), cxJumps.end(), decodedInstr->getMnemonic()) != cxJumps.end()) {
        instruction = checkCx(decodedInstr, instruction);
    }
    auto target = decodedInstr->getOperands()[0];
    if (target->isGeneralPurposeRegister()) {
        return checkReg(instruction, decodedInstr);
    } else if (target->isMemory()) {
        return checkMem(instruction, decodedInstr);
    }
    return instruction;
}

/**
 * Inserts instrumentation before <code>instruction</code> that verifies whether EFLAGS is defined. If
 * it is not, an MSan warning is issued.
 * @param instruction instruction that jumps based on EFLAGS, like "je"
 */
IRDB_SDK::Instruction_t *ControlFlowHandler::checkRflags(Instruction_t *instruction) {
    string instrumentation = Utils::getStateSavingInstrumentation() +
                            "lea rsp, [rsp + 0xd0]\n" +
                            "call 0\n" +
                            "lea rsp, [rsp - 0xd0]\n" +
                             Utils::getStateRestoringInstrumentation();
    const auto new_instr = insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation, {});
    auto calls = DisassemblyService::getCallInstructionPosition(new_instr);
    new_instr[calls[0]]->setTarget(RuntimeLib::checkRflags);
    return new_instr.back();
}

/**
 * Inserts instrumentation before <code>instruction</code> that verifies whether the respective part of
 * RCX/ECX/CX is defined. If it is not, an MSan warning is issued.
 * @param instruction instruction that jumps based on RCX, like "jrcxz"
 */
IRDB_SDK::Instruction_t *
ControlFlowHandler::checkCx(unique_ptr<IRDB_SDK::DecodedInstruction_t> &decodedInstr, Instruction_t *instruction) {
    int width = WORD;
    if (decodedInstr->getMnemonic() == "jecxz") {
        width = DOUBLE_WORD;
    } else if (decodedInstr->getMnemonic() == "jrcxz") {
        width = QUAD_WORD;
    }
    string instrumentation = Utils::getStateSavingInstrumentation() +
            "mov rdi, %%1" +
            "mov rsi, %%2" +
            "lea rsp, [rsp + 0xd0]\n" +
            "call 0\n" +
            "lea rsp, [rsp - 0xd0]\n" +
            Utils::getStateRestoringInstrumentation();
    const auto new_instr = insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation,
                                                            {to_string(RCX), to_string(Utils::toHex(width))});
    auto calls = DisassemblyService::getCallInstructionPosition(new_instr);
    new_instr[calls[0]]->setTarget(RuntimeLib::checkRegIsInit);
    return new_instr.back();
}


/**
 * Inserts instrumentation before <code>instruction</code> that verifies whether the register used to indicate
 * the jump/call target is initialised. If it is not, an MSan warning is issued.
 */
IRDB_SDK::Instruction_t *
ControlFlowHandler::checkReg(Instruction_t *instruction, unique_ptr<DecodedInstruction_t> &decodedInstr) {
    auto reg = decodedInstr->getOperand(0)->getRegNumber();
    auto width = disassemblyService->getRegWidth(instruction, 0);
    string instrumentation = Utils::getStateSavingInstrumentation() +
                             "mov rdi, %%1\n" +      // reg
                             "mov rsi, %%2\n" +      // regWidth
                             "lea rsp, [rsp + 0xd0]\n" +
                             "call 0\n" +            // checkRegIsInit
                             "lea rsp, [rsp - 0xd0]\n" +
                             Utils::getStateRestoringInstrumentation();
    vector<basic_string<char>> instrumentationParams{to_string(reg), to_string(width)};
    const auto new_instr = insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation,
                                                                        instrumentationParams);
    auto calls = DisassemblyService::getCallInstructionPosition(new_instr);
    new_instr[calls[0]]->setTarget(RuntimeLib::checkRegIsInit);
    return new_instr.back();
}

/**
 * Inserts instrumentation before <code>instruction</code> that verifies whether the memory address of
 * the jump/call target is initialised. If it is not, an MSan warning is issued.
 */
IRDB_SDK::Instruction_t *
ControlFlowHandler::checkMem(IRDB_SDK::Instruction_t *instruction, unique_ptr<DecodedInstruction_t> &decodedInstr) {
    auto memOperand = disassemblyService->getMemoryOperandDisassembly(instruction);
    // Zipr does not seem to support the instruction "call qword [r15 + rbx*8]" (binary: 0x41 0xff 0x14 0xdf)
    // because it does not recognise the second byte (0xff) as the beginning of a call instruction. Skip it for now.
    // See: zipr/src/patcher_x86.cpp, function ZiprPatcherX86_t::ApplyPatch
    if (decodedInstr->getPrefixCount() > 0){
        return instruction;
    }
    auto width = decodedInstr->getOperand(0)->getArgumentSizeInBytes();
    string instrumentation = Utils::getStateSavingInstrumentation() +
                             "lea rdi, %%1\n" +      // x
                             "mov rsi, %%2\n" +      // size
                             "call 0\n" +            // __msan_check_mem_is_initialized
                             Utils::getStateRestoringInstrumentation();
    vector<basic_string<char>> instrumentationParams{memOperand, to_string(width)};
    const auto new_instr = insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation,
                                                                        instrumentationParams);
    auto calls = DisassemblyService::getCallInstructionPosition(new_instr);
    new_instr[calls[0]]->setTarget(RuntimeLib::msan_check_mem_is_initialized);
    return new_instr.back();
}

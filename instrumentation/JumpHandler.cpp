#include "JumpHandler.h"
#include "../common/RegisterNumbering.h"
#include "../common/Width.h"
#include "RuntimeLib.h"
#include "Utils.h"

using namespace IRDB_SDK;
using namespace std;

JumpHandler::JumpHandler(FileIR_t *fileIr) : fileIr(fileIr) {
    capstone = make_unique<DisassemblyService>();
}

const std::vector<std::string> &JumpHandler::getAssociatedInstructions() {
    return associatedInstructions;
}

void JumpHandler::instrument(Instruction_t *instruction) {
    cout << "JumpHandler. Instruction: " << instruction->getDisassembly() << " at " << instruction->getAddress()->getVirtualOffset() << endl;

    auto decodedInstr =  DecodedInstruction_t::factory(instruction);
    for(auto &cxInstruction : cxInstructions){
        if(decodedInstr->getMnemonic() == cxInstruction){
            checkCx(decodedInstr, instruction);
            return;
        }
    }
    checkEflags(instruction);
}

/**
 * Inserts instrumentation before <code>instruction</code> that verifies whether EFLAGS is defined. If
 * it is not, an MSan warning is issued.
 * @param instruction instruction that jumps based on EFLAGS, like "je"
 */
void JumpHandler::checkEflags(Instruction_t *instruction) {
    string instrumentation = string() +
            Utils::getStateSavingInstrumentation() +
                             "call 0\n" +
            Utils::getStateRestoringInstrumentation();
    const auto new_instr = insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation,{});
    auto calls = DisassemblyService::getCallInstructionPosition(new_instr);
    new_instr[calls[0]]->setTarget(RuntimeLib::checkEflags);
}

/**
 * Inserts instrumentation before <code>instruction</code> that verifies whether the respective part of
 * RCX/ECX/CX is defined. If it is not, an MSan warning is issued.
 * @param instruction instruction that jumps based on RCX, like "jrcxz"
 */
void JumpHandler::checkCx(unique_ptr<IRDB_SDK::DecodedInstruction_t> &decodedInstr, Instruction_t *instruction) {
    int width = WORD;
    if(decodedInstr->getMnemonic() == "jecxz"){
        width = DOUBLE_WORD;
    } else if (decodedInstr->getMnemonic() == "jrcxz"){
        width = QUAD_WORD;
    }
    string instrumentation = string() +
            Utils::getStateSavingInstrumentation() +
                             "mov rdi, %%1" +
                             "mov rsi, %%2"
                             "call 0\n" +
            Utils::getStateRestoringInstrumentation();
    const auto new_instr = insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation,{to_string(RCX), to_string(Utils::toHex(width))});
    auto calls = DisassemblyService::getCallInstructionPosition(new_instr);
	new_instr[calls[0]]->setTarget(RuntimeLib::checkRegIsInit);
}


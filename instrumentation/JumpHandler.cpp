#include "JumpHandler.h"
#include "../common/RegisterNumbering.h"

using namespace IRDB_SDK;
using namespace std;

JumpHandler::JumpHandler(FileIR_t *fileIr) : fileIr(fileIr) {
    capstone = make_unique<CapstoneService>();
}

const std::vector<std::string> &JumpHandler::getAssociatedInstructions() {
    return associatedInstructions;
}

//TODO: check out all jumps that can be handled like this
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

void JumpHandler::checkEflags(Instruction_t *instruction) {
    string instrumentation = string() +
                             Utils::getPushCallerSavedRegistersInstrumentation() +
                             "call 0\n" +
                             Utils::getPopCallerSavedRegistersInstrumentation();
    const auto new_instr = insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation,{});
    auto calls = CapstoneService::getCallInstructionPosition(new_instr);
    new_instr[calls[0]]->setTarget(RuntimeLib::checkEflags);
}

void JumpHandler::checkCx(unique_ptr<IRDB_SDK::DecodedInstruction_t> &decodedInstr, Instruction_t *instruction) {
    int width = WORD;
    if(decodedInstr->getMnemonic() == "jecxz"){
        width = DOUBLE_WORD;
    } else if (decodedInstr->getMnemonic() == "jrcxz"){
        width = QUAD_WORD;
    }
    string instrumentation = string() +
                             Utils::getPushCallerSavedRegistersInstrumentation() +
                             "mov rdi, %%1" +
                             "mov rsi, %%2"
                             "call 0\n" +
                             Utils::getPopCallerSavedRegistersInstrumentation();
    const auto new_instr = insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation,{to_string(RCX), to_string(Utils::toHex(width))});
    auto calls = CapstoneService::getCallInstructionPosition(new_instr);
	new_instr[calls[0]]->setTarget(RuntimeLib::checkRegIsInit);
}


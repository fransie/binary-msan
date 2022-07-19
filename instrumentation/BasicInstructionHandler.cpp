#include "BasicInstructionHandler.h"

using namespace IRDB_SDK;

BasicInstructionHandler::BasicInstructionHandler(IRDB_SDK::FileIR_t *fileIr) : fileIr(fileIr) {}

const std::vector<std::string> &BasicInstructionHandler::getAssociatedInstructions() {
    return associatedInstructions;
}

void BasicInstructionHandler::instrument(IRDB_SDK::Instruction_t *instruction) {
    auto decodedInstruction = DecodedInstruction_t::factory(instruction);
    vector<shared_ptr<DecodedOperand_t>> operands = decodedInstruction->getOperands();
    if(operands[0]->isGeneralPurposeRegister()){
        if(operands[1]->isGeneralPurposeRegister()){
            instrumentRegRegInstruction(instruction);
        } else if (operands[1]->isMemory()) {
            instrumentRegMemInstruction(instruction);
        }
        // No instrumentation needed for immediate source operands since the resulting shadow value
    } else if (operands[0]->isMemory()) {
        if(operands[1]->isGeneralPurposeRegister()){
            instrumentMemRegInstruction(instruction);
        }
        // No instrumentation needed for immediate source operands since the resulting shadow value
        // of the destination memory location fully depends on itself.
    }
}

void BasicInstructionHandler::instrumentRegRegInstruction(IRDB_SDK::Instruction_t *instruction) {

}

void BasicInstructionHandler::instrumentMemRegInstruction(IRDB_SDK::Instruction_t *instruction) {

}

void BasicInstructionHandler::instrumentRegMemInstruction(IRDB_SDK::Instruction_t *instruction) {

}



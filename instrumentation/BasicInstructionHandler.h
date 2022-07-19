#ifndef BINARY_MSAN_BASICINSTRUCTIONHANDLER_H
#define BINARY_MSAN_BASICINSTRUCTIONHANDLER_H

#include "InstructionHandler.h"

class BasicInstructionHandler : public InstructionHandler {
public:
    explicit BasicInstructionHandler(IRDB_SDK::FileIR_t *fileIr);

    void instrument(IRDB_SDK::Instruction_t *instruction) override;

    const std::vector<std::string> &getAssociatedInstructions() override;
private:
    std::vector<std::string> associatedInstructions {"add", "xor"};
    IRDB_SDK::FileIR_t *fileIr;

    void instrumentRegRegInstruction(IRDB_SDK::Instruction_t *instruction);

    void instrumentMemRegInstruction(IRDB_SDK::Instruction_t *instruction);

    void instrumentRegMemInstruction(IRDB_SDK::Instruction_t *instruction);
};


#endif //BINARY_MSAN_BASICINSTRUCTIONHANDLER_H

#ifndef BINARY_MSAN_BASICINSTRUCTIONHANDLER_H
#define BINARY_MSAN_BASICINSTRUCTIONHANDLER_H

#include "InstructionHandler.h"
#include "DisassemblyService.h"

class BasicInstructionHandler : public InstructionHandler {
public:
    explicit BasicInstructionHandler(IRDB_SDK::FileIR_t *fileIr);
    ~BasicInstructionHandler() = default;

    void instrument(IRDB_SDK::Instruction_t *instruction) override;
    const std::vector<std::string> &getAssociatedInstructions() override;
private:
    std::vector<std::string> associatedInstructions {"add", "xor"};
    std::unique_ptr<DisassemblyService> capstone;
    IRDB_SDK::FileIR_t *fileIr;

    void instrumentMemRegInstruction(IRDB_SDK::Instruction_t *instruction);
    void instrumentRegMemInstruction(IRDB_SDK::Instruction_t *instruction);
    void instrumentRegRegInstruction(IRDB_SDK::Instruction_t *instruction);
};


#endif //BINARY_MSAN_BASICINSTRUCTIONHANDLER_H

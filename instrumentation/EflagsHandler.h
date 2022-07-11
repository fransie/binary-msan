#ifndef BINARY_MSAN_EFLAGSHANDLER_H
#define BINARY_MSAN_EFLAGSHANDLER_H


#include "InstructionHandler.h"
#include "DisassemblyService.h"

class EflagsHandler : public InstructionHandler {
public:
    explicit EflagsHandler(IRDB_SDK::FileIR_t *fileIr);
    ~EflagsHandler() = default;
    void instrument(IRDB_SDK::Instruction_t *instruction) override;

    const std::vector<std::string> &getAssociatedInstructions() override;
private:
    std::vector<std::string> associatedInstructions {"cmp", "test"};
    std::unique_ptr<DisassemblyService> capstone;

    IRDB_SDK::FileIR_t *fileIr;

    void propagateRegShadowToEflags(IRDB_SDK::Instruction_t *instruction);
    void propagateMemShadowToEflags(IRDB_SDK::Instruction_t *instruction);
    void propagateRegOrRegShadowToEflags(IRDB_SDK::Instruction_t *instruction);
    void propagateRegOrMemShadowToEflags(IRDB_SDK::Instruction_t *instruction);
};


#endif //BINARY_MSAN_EFLAGSHANDLER_H

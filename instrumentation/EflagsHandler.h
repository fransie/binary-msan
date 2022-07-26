#ifndef BINARY_MSAN_EFLAGSHANDLER_H
#define BINARY_MSAN_EFLAGSHANDLER_H


#include "InstructionHandler.h"
#include "DisassemblyService.h"

class EflagsHandler : public InstructionHandler {
public:
    explicit EflagsHandler(IRDB_SDK::FileIR_t *fileIr);
    ~EflagsHandler() = default;

    bool isResponsibleFor(IRDB_SDK::Instruction_t *instruction) override;
    IRDB_SDK::Instruction_t* instrument(IRDB_SDK::Instruction_t *instruction) override;

private:
    std::vector<std::string> associatedInstructions {"cmp", "test"};
    std::unique_ptr<DisassemblyService> capstone;

    IRDB_SDK::FileIR_t *fileIr;

    IRDB_SDK::Instruction_t* propagateRegShadowToEflags(IRDB_SDK::Instruction_t *instruction);
    IRDB_SDK::Instruction_t* propagateMemShadowToEflags(IRDB_SDK::Instruction_t *instruction);
    IRDB_SDK::Instruction_t* propagateRegOrRegShadowToEflags(IRDB_SDK::Instruction_t *instruction);
    IRDB_SDK::Instruction_t* propagateRegOrMemShadowToEflags(IRDB_SDK::Instruction_t *instruction);
};


#endif //BINARY_MSAN_EFLAGSHANDLER_H

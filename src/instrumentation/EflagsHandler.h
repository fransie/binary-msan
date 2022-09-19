#ifndef BINARY_MSAN_EFLAGSHANDLER_H
#define BINARY_MSAN_EFLAGSHANDLER_H

#include "InstructionHandler.h"
#include "DisassemblyService.h"

/**
 * Handles instructions that affect the EFLAGS register but discard their result, i.e. cmp and test.
 * The shadow of the result is calculated and used to poison or unpoison EFLAGS accordingly.
 */
class EflagsHandler : public InstructionHandler {
public:
    explicit EflagsHandler(IRDB_SDK::FileIR_t *fileIr) : InstructionHandler(fileIr) {
        associatedInstructions = {"cmp", "test"};
    };

    IRDB_SDK::Instruction_t *instrument(IRDB_SDK::Instruction_t *instruction) override;

private:
    IRDB_SDK::Instruction_t *propagateRegShadowToEflags(IRDB_SDK::Instruction_t *instruction);
    IRDB_SDK::Instruction_t *propagateMemShadowToEflags(IRDB_SDK::Instruction_t *instruction);
    IRDB_SDK::Instruction_t *propagateRegOrRegShadowToEflags(IRDB_SDK::Instruction_t *instruction);
    IRDB_SDK::Instruction_t *propagateRegOrMemShadowToEflags(IRDB_SDK::Instruction_t *instruction);
};


#endif //BINARY_MSAN_EFLAGSHANDLER_H

#ifndef BINARY_MSAN_RFLAGSHANDLER_H
#define BINARY_MSAN_RFLAGSHANDLER_H

#include "InstructionHandler.h"
#include "DisassemblyService.h"

/**
 * Handles instructions that affect the RFLAGS register but discard their result, i.e. cmp and test.
 * The shadow of the result is calculated and used to poison or unpoison RFLAGS accordingly.
 */
class RflagsHandler : public InstructionHandler {
public:
    explicit RflagsHandler(IRDB_SDK::FileIR_t *fileIr) : InstructionHandler(fileIr) {
        associatedInstructions = {"cmp", "test"};
    };

    IRDB_SDK::Instruction_t *instrument(IRDB_SDK::Instruction_t *instruction) override;

private:
    IRDB_SDK::Instruction_t *propagateRegShadowToRflags(IRDB_SDK::Instruction_t *instruction);
    IRDB_SDK::Instruction_t *propagateMemShadowToRflags(IRDB_SDK::Instruction_t *instruction);
    IRDB_SDK::Instruction_t *propagateRegOrRegShadowToRflags(IRDB_SDK::Instruction_t *instruction);
    IRDB_SDK::Instruction_t *propagateRegOrMemShadowToRflags(IRDB_SDK::Instruction_t *instruction);
};


#endif //BINARY_MSAN_RFLAGSHANDLER_H

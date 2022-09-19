#ifndef BINARY_MSAN_LEAHANDLER_H
#define BINARY_MSAN_LEAHANDLER_H

#include "InstructionHandler.h"

/**
 * Handles the lea instruction. The destination register will be poisoned if any of the registers used in the
 * memory operand have at least one poisoned bit, otherwise it will be unpoisoned.
 */
class LeaHandler : public InstructionHandler {
public:
    explicit LeaHandler(IRDB_SDK::FileIR_t *fileIr) : InstructionHandler(fileIr) {
        associatedInstructions = {"lea"};
    };

    IRDB_SDK::Instruction_t *instrument(IRDB_SDK::Instruction_t *instruction) override;

private:
    IRDB_SDK::Instruction_t *instrumentImmLea(IRDB_SDK::Instruction_t *instruction);
    IRDB_SDK::Instruction_t *instrumentRegRegLea(IRDB_SDK::Instruction_t *instruction);
    IRDB_SDK::Instruction_t *instrumentRegLea(IRDB_SDK::Instruction_t *instruction);
};

#endif //BINARY_MSAN_LEAHANDLER_H

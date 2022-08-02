#ifndef BINARY_MSAN_BINARYARITHMETICHANDLER_H
#define BINARY_MSAN_BINARYARITHMETICHANDLER_H

#include "InstructionHandler.h"
#include "DisassemblyService.h"

/**
 * Handles the correct shadow propagation of binary arithmetic instructions such as add, xor, and so on.
 * Two steps will be performed: 1) The shadow of the result will be computed as the OR of the
 * shadow of the two operands and 2) the definedness of the EFLAGS register will be set according
 * to whether the result of the instruction is fully defined. Hence, this Handler should only be used
 * for instructions that affect at least one of the EFLAGS flags.
 */
class BinaryArithmeticHandler : public InstructionHandler {
public:
    explicit BinaryArithmeticHandler(IRDB_SDK::FileIR_t *fileIr) : InstructionHandler(fileIr) {
        associatedInstructions = {"add", "sub"};
    }

    IRDB_SDK::Instruction_t * instrument(IRDB_SDK::Instruction_t *instruction) override;

private:
    IRDB_SDK::Instruction_t* instrumentMemRegInstruction(IRDB_SDK::Instruction_t *instruction);
    IRDB_SDK::Instruction_t* instrumentMemImmInstruction(IRDB_SDK::Instruction_t *instruction);
    IRDB_SDK::Instruction_t* instrumentRegImm(IRDB_SDK::Instruction_t *instruction);
    IRDB_SDK::Instruction_t* instrumentRegMemInstruction(IRDB_SDK::Instruction_t *instruction);
    IRDB_SDK::Instruction_t* instrumentRegRegInstruction(IRDB_SDK::Instruction_t *instruction);
};


#endif //BINARY_MSAN_BINARYARITHMETICHANDLER_H

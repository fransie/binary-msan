#ifndef BINARY_MSAN_LEAHANDLER_H
#define BINARY_MSAN_LEAHANDLER_H

#include "InstructionHandler.h"

class LeaHandler : public InstructionHandler {
public:
    explicit LeaHandler(IRDB_SDK::FileIR_t *fileIr) : InstructionHandler(fileIr) {
        associatedInstructions = {"lea"};
    };

    IRDB_SDK::Instruction_t* instrument(IRDB_SDK::Instruction_t *instruction) override;
private:
    IRDB_SDK::Instruction_t* instrumentImmLea(IRDB_SDK::Instruction_t *instruction);
    IRDB_SDK::Instruction_t* instrumentRegRegLea(IRDB_SDK::Instruction_t *instruction);
    IRDB_SDK::Instruction_t* instrumentRegLea(IRDB_SDK::Instruction_t *instruction);
};
#endif //BINARY_MSAN_LEAHANDLER_H

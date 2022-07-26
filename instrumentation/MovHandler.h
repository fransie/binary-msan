#ifndef BINARY_MSAN_MOVHANDLER_H
#define BINARY_MSAN_MOVHANDLER_H

#include <irdb-core>
#include "DisassemblyService.h"
#include "InstructionHandler.h"

class MovHandler : public InstructionHandler {
public:
    explicit MovHandler(IRDB_SDK::FileIR_t *fileIr) : InstructionHandler(fileIr) {
        associatedInstructions = {"mov"};
    };

    IRDB_SDK::Instruction_t* instrument(IRDB_SDK::Instruction_t *instruction) override;

private:
    IRDB_SDK::Instruction_t* instrumentImmToRegMove(IRDB_SDK::Instruction_t *instruction);
    IRDB_SDK::Instruction_t* instrumentImmToMemMove(IRDB_SDK::Instruction_t *instruction);
    IRDB_SDK::Instruction_t* instrumentMemToRegMove(IRDB_SDK::Instruction_t *instruction);
    IRDB_SDK::Instruction_t* instrumentRegToMemMove(IRDB_SDK::Instruction_t *instruction);
    IRDB_SDK::Instruction_t* instrumentRegToRegMove(IRDB_SDK::Instruction_t *instruction);
};


#endif //BINARY_MSAN_MOVHANDLER_H

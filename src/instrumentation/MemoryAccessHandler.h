#ifndef BINARY_MSAN_MEMORYACCESSHANDLER_H
#define BINARY_MSAN_MEMORYACCESSHANDLER_H

#include <irdb-core>
#include "InstructionHandler.h"

/**
 * Handles memory dereferences for all instructions containing a memory operand. Lea is the only exception since
 * it has a memory operand which is not dereferenced.
 */
class MemoryAccessHandler : public InstructionHandler {
public:
    explicit MemoryAccessHandler(IRDB_SDK::FileIR_t *fileIr) : InstructionHandler(fileIr) {};

    IRDB_SDK::Instruction_t* instrument(IRDB_SDK::Instruction_t *instruction) override;
    bool isResponsibleFor(IRDB_SDK::Instruction_t *instruction) override;

private:
    static bool hasMemoryOperand(std::unique_ptr<IRDB_SDK::DecodedInstruction_t> &instruction);
};


#endif //BINARY_MSAN_MEMORYACCESSHANDLER_H

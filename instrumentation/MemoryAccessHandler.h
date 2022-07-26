#ifndef BINARY_MSAN_MEMORYACCESSHANDLER_H
#define BINARY_MSAN_MEMORYACCESSHANDLER_H

#include <irdb-core>
#include "DisassemblyService.h"
#include "InstructionHandler.h"


class MemoryAccessHandler : public InstructionHandler {
public:
    explicit MemoryAccessHandler(IRDB_SDK::FileIR_t *fileIr);


    IRDB_SDK::Instruction_t* instrument(IRDB_SDK::Instruction_t *instruction) override;
    bool isResponsibleFor(IRDB_SDK::Instruction_t *instruction) override;

private:
    IRDB_SDK::FileIR_t *fileIr;
    std::unique_ptr<DisassemblyService> disassemblyService;

    static bool hasMemoryOperand(std::unique_ptr<IRDB_SDK::DecodedInstruction_t> &instruction);
};


#endif //BINARY_MSAN_MEMORYACCESSHANDLER_H

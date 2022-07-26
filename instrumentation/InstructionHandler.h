
#ifndef BINARY_MSAN_INSTRUCTIONHANDLER_H
#define BINARY_MSAN_INSTRUCTIONHANDLER_H

#include <irdb-core>
#include "DisassemblyService.h"

class InstructionHandler {
public:
    explicit InstructionHandler(IRDB_SDK::FileIR_t *fileIr) : fileIr(fileIr) {
        disassemblyService = std::make_unique<DisassemblyService>();
    }
    ~InstructionHandler() = default;

    /**
     * Inserts appropriate instrumentation and return the original instruction.
     * @param instruction instruction to be instrumented.
     * @return original instruction.
     */
    virtual IRDB_SDK::Instruction_t* instrument(IRDB_SDK::Instruction_t *instruction) = 0;

    /**
     * Tells whether this handler is responsible for instrumenting the input instruction.
     * @param instruction input instruction.
     * @return true if handler is responsible.
     */
    virtual bool isResponsibleFor(IRDB_SDK::Instruction_t *instruction) = 0;

protected:
    std::unique_ptr<DisassemblyService> disassemblyService;
    IRDB_SDK::FileIR_t *fileIr;
};


#endif //BINARY_MSAN_INSTRUCTIONHANDLER_H

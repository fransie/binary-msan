
#ifndef BINARY_MSAN_INSTRUCTIONHANDLER_H
#define BINARY_MSAN_INSTRUCTIONHANDLER_H

#include <irdb-core>

class InstructionHandler {
public:
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
};


#endif //BINARY_MSAN_INSTRUCTIONHANDLER_H

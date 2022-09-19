#ifndef BINARY_MSAN_INSTRUCTIONHANDLER_H
#define BINARY_MSAN_INSTRUCTIONHANDLER_H

#include <irdb-core>
#include "DisassemblyService.h"

/**
 * Interface that handlers for instructions must implement.
 */
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
    virtual bool isResponsibleFor(IRDB_SDK::Instruction_t *instruction){
        auto decodedInstruction = IRDB_SDK::DecodedInstruction_t::factory(instruction);
        auto mnemonic = decodedInstruction->getMnemonic();
        for (const auto& associatedInstruction : associatedInstructions){
            if (associatedInstruction == mnemonic){
                return true;
            }
        }
        return false;
    }

protected:
    std::unique_ptr<DisassemblyService> disassemblyService;
    IRDB_SDK::FileIR_t *fileIr;
    std::vector<std::string> associatedInstructions {};
};


#endif //BINARY_MSAN_INSTRUCTIONHANDLER_H

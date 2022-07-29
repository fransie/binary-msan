#ifndef BINARY_MSAN_MSAN_H
#define BINARY_MSAN_MSAN_H

#include <irdb-core>
#include <irdb-transform>
#include "FunctionHandler.h"
#include "InstructionHandler.h"
#include "MemoryAccessHandler.h"

class MSan : protected IRDB_SDK::Transform_t
{
public:
    MSan(IRDB_SDK::FileIR_t *fileIR);
    //TODO: clean up in destructor
    //~MSan() override;

    bool executeStep();
    bool parseArgs(std::vector<std::string> step_args);
    bool parseArgs(int argc, char* argv[]);
private:
    bool halt_on_error = true;
    std::vector<std::unique_ptr<InstructionHandler>> instructionHandlers;
    std::vector<std::unique_ptr<FunctionHandler>> functionHandlers;

    void registerDependencies();
    void initGpRegisters(IRDB_SDK::Instruction_t *instruction);
    void disableHaltOnError(IRDB_SDK::Instruction_t *instruction);
};

#endif

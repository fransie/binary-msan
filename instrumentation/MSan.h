#ifndef BINARY_MSAN_MSAN_H
#define BINARY_MSAN_MSAN_H

#include <irdb-core>
#include <irdb-transform>
#include "FunctionHandler.h"
#include "InstructionHandler.h"
#include "MemoryAccessHandler.h"

class MSan : protected IRDB_SDK::Transform_t {
public:
    explicit MSan(IRDB_SDK::FileIR_t *fileIR);

    bool executeStep();

    bool parseArgs(std::vector<std::string> step_args);
    bool parseArgs(int argc, char *argv[]);

private:
    bool keep_going = false;
    bool logging = false;
    std::vector<std::unique_ptr<InstructionHandler>> instructionHandlers;
    std::vector<std::unique_ptr<FunctionHandler>> functionHandlers;

    void registerDependencies();
    void instrumentOptions(IRDB_SDK::Instruction_t *instruction);
};

#endif

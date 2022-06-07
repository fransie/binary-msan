//
// Created by Franziska Mäckel on 03.04.22.
//

#ifndef BINARY_MSAN_MSAN_H
#define BINARY_MSAN_MSAN_H

#include <irdb-core>
#include <irdb-transform>
#include <irdb-elfdep>
#include <memory>
#include "JumpHandler.h"
#include "MovHandler.h"
#include "TestHandler.h"
#include "RuntimeLib.h"

class MSan : protected IRDB_SDK::Transform_t
{
public:
    MSan(IRDB_SDK::FileIR_t *fileIR);
    //TODO: clean up in destructor
    //~MSan() override;

    bool executeStep();
    bool parseArgs(std::vector<std::string> step_args);

private:
    std::vector<std::unique_ptr<Handler>> handlers;

    void registerDependencies();

    void initGpRegisters(IRDB_SDK::Instruction_t *instruction);
};

#endif

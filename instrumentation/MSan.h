//
// Created by Franziska Mäckel on 03.04.22.
//

#ifndef BINARY_MSAN_MSAN_H
#define BINARY_MSAN_MSAN_H

#include <irdb-core>
#include <irdb-transform>
#include <irdb-elfdep>
#include <memory>
#include "MovHandler.h"
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
    std::unique_ptr<MovHandler> movHandler;

    void registerDependencies();
    void addHandler(IRDB_SDK::Instruction_t *instruction);

};

#endif

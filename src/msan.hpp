//
// Created by Franziska Mäckel on 03.04.22.
//

#ifndef BINARY_MSAN_MSAN_H
#define BINARY_MSAN_MSAN_H

#include <irdb-core>
#include <irdb-transform>
#include <irdb-deep>
#include <capstone.h>
#include "CapstoneService.h"

class MSan : protected IRDB_SDK::Transform_t
{
public:
    MSan(IRDB_SDK::FileIR_t *fileIR);
    //TODO: clean up in destructor
    //~MSan() override;

    bool executeStep();
    bool parseArgs(std::vector<std::string> step_args);


private:
    void registerDependencies();
    void moveHandler(IRDB_SDK::Instruction_t *instruction);
    void addHandler(IRDB_SDK::Instruction_t *instruction);
    void instrumentImmediateToRegMove(IRDB_SDK::Instruction_t *instruction);
    void instrumentRegToRegMove(IRDB_SDK::Instruction_t *instruction);
    void instrumentMemToRegMove(IRDB_SDK::Instruction_t *instruction);
    void instrumentMemRef(const std::shared_ptr<IRDB_SDK::DecodedOperand_t>& operand, IRDB_SDK::Instruction_t *instruction);

    IRDB_SDK::Instruction_t *regToRegShadowCopy;
    IRDB_SDK::Instruction_t *defineRegShadow;
    IRDB_SDK::Instruction_t *checkMemComponentsInit;

    std::unique_ptr<CapstoneService> capstoneService;

};

#endif

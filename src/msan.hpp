//
// Created by Franziska Mäckel on 03.04.22.
//

#ifndef BINARY_MSAN_MSAN_H
#define BINARY_MSAN_MSAN_H

#include <irdb-core>
#include <irdb-transform>
#include <irdb-deep>
#include <capstone.h>


class MSan : protected IRDB_SDK::Transform_t
{
public:
    MSan(IRDB_SDK::FileIR_t *fileIR);
    ~MSan() override;

    bool executeStep();
    bool parseArgs(std::vector<std::string> step_args);


private:
    std::string getPushCallerSavedRegistersInstrumentation();
    std::string getPopCallerSavedRegistersInstrumentation();
    void registerDependencies();
    void moveHandler(IRDB_SDK::Instruction_t *instruction);
    void addHandler(IRDB_SDK::Instruction_t *instruction);
    void instrumentRegToRegMove(IRDB_SDK::Instruction_t *instruction);
    void setUpCapstone();
    x86_reg getCapstoneRegister(IRDB_SDK::Instruction_t *instruction);
    bool isHigherByteRegister(x86_reg capstoneRegNumber);

    csh capstoneHandle;
    IRDB_SDK::Instruction_t *regToRegShadowCopy;
    IRDB_SDK::Instruction_t *defineRegShadow;

    void instrumentImmediateToRegMove(IRDB_SDK::Instruction_t *instruction);
};

#endif

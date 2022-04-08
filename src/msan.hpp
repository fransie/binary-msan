//
// Created by Franziska Mäckel on 03.04.22.
//

#ifndef BINARY_MSAN_MSAN_H
#define BINARY_MSAN_MSAN_H

#include <irdb-core>
#include <irdb-transform>
#include <irdb-deep>


class MSan : protected IRDB_SDK::Transform_t
{
public:
    MSan(IRDB_SDK::FileIR_t *fileIR);

    bool executeStep();
    bool parseArgs(std::vector<std::string> step_args);


    std::vector<uint64_t> shadowRegisters;


private:
    void regToRegMove(int dest, int source);
    std::string getPushCallerSavedRegistersInstrumentation();
    std::string getPopCallerSavedRegistersInstrumentation();
    void registerDependencies();
    void moveHandler(IRDB_SDK::Instruction_t *instruction);

    IRDB_SDK::Instruction_t *regToRegMoveFunction;
};

#endif

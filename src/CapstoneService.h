//
// Created by Franziska Mäckel on 12.04.22.
//

#ifndef BINARY_MSAN_CAPSTONESERVICE_H
#define BINARY_MSAN_CAPSTONESERVICE_H


#include <capstone.h>
#include <irdb-core>
#include <irdb-transform>
#include <irdb-deep>

class CapstoneService {
public:
    CapstoneService();
    ~CapstoneService();

    x86_reg getRegister(IRDB_SDK::Instruction_t *instruction, int operandNumber);
    bool isHigherByteRegister(x86_reg capstoneRegNumber);
    int getOperandWidth(IRDB_SDK::Instruction_t *instruction);


private:
    csh capstoneHandle;



};


#endif //BINARY_MSAN_CAPSTONESERVICE_H

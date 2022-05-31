//
// Created by Franziska Mäckel on 12.04.22.
//

#ifndef BINARY_MSAN_CAPSTONESERVICE_H
#define BINARY_MSAN_CAPSTONESERVICE_H


#include <capstone.h>
#include <irdb-core>

class CapstoneService {
public:
    CapstoneService();
    ~CapstoneService();

    x86_reg getRegister(IRDB_SDK::Instruction_t *instruction, int operandNumber);
    bool isHigherByteRegister(x86_reg capstoneRegNumber);
    int getOperandWidth(IRDB_SDK::Instruction_t *instruction);
    int getBaseRegWidth(IRDB_SDK::Instruction_t *instruction);
    int getIndexRegWidth(IRDB_SDK::Instruction_t *instruction);


private:
    csh capstoneHandle;
    cs_insn* getCapstoneInstruction(IRDB_SDK::Instruction_t *instruction);
    static int convertX86RegNumberToWidth(x86_reg regNumber);
    static int toHex(int num);
    static int getPositionOfMemOperand(cs_insn *capstoneInstruction);

};


#endif //BINARY_MSAN_CAPSTONESERVICE_H
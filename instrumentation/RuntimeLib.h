//
// Created by Franziska Mäckel on 05.06.22.
//

#ifndef BINARY_MSAN_RUNTIMELIB_H
#define BINARY_MSAN_RUNTIMELIB_H

#include <irdb-core>

class RuntimeLib {
public:
    inline static IRDB_SDK::Instruction_t *defineRegShadow;
    inline static IRDB_SDK::Instruction_t *checkRegIsInit;
    inline static IRDB_SDK::Instruction_t *memToRegShadowCopy;
    inline static IRDB_SDK::Instruction_t *regToRegShadowCopy;
    inline static IRDB_SDK::Instruction_t *setFlagsAfterTest_Reg;
    inline static IRDB_SDK::Instruction_t *setFlagsAfterTest_RegReg;
};


#endif //BINARY_MSAN_RUNTIMELIB_H

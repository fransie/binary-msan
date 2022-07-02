//
// Created by Franziska Mäckel on 05.06.22.
//

#ifndef BINARY_MSAN_RUNTIMELIB_H
#define BINARY_MSAN_RUNTIMELIB_H

#include <irdb-core>

class RuntimeLib {
public:
    inline static IRDB_SDK::Instruction_t *defineRegShadow;
    inline static IRDB_SDK::Instruction_t *__msan_unpoison;
    inline static IRDB_SDK::Instruction_t *checkRegIsInit;
    inline static IRDB_SDK::Instruction_t *memToRegShadowCopy;
    inline static IRDB_SDK::Instruction_t *regToRegShadowCopy;
    inline static IRDB_SDK::Instruction_t *regToMemShadowCopy;
    inline static IRDB_SDK::Instruction_t *checkEflags;
    inline static IRDB_SDK::Instruction_t *initGpRegisters;
    inline static IRDB_SDK::Instruction_t *__msan_set_keep_going;
    inline static IRDB_SDK::Instruction_t *__msan_poison_stack;
    inline static IRDB_SDK::Instruction_t *isRegFullyDefined;
    inline static IRDB_SDK::Instruction_t *isMemFullyDefined;
    inline static IRDB_SDK::Instruction_t *isRegOrRegFullyDefined;
    inline static IRDB_SDK::Instruction_t *isRegOrMemFullyDefined;
    inline static IRDB_SDK::Instruction_t *setEflags;
    inline static IRDB_SDK::Instruction_t *setRegShadow;
    inline static IRDB_SDK::Instruction_t *setMemShadow;
};


#endif //BINARY_MSAN_RUNTIMELIB_H


#ifndef BINARY_MSAN_RUNTIMELIB_H
#define BINARY_MSAN_RUNTIMELIB_H

#include <irdb-core>

class RuntimeLib {
public:
    inline static IRDB_SDK::Instruction_t *msan_unpoison;
    inline static IRDB_SDK::Instruction_t *checkRegIsInit;
    inline static IRDB_SDK::Instruction_t *memToRegShadowCopy;
    inline static IRDB_SDK::Instruction_t *regToRegShadowCopy;
    inline static IRDB_SDK::Instruction_t *regToMemShadowCopy;
    inline static IRDB_SDK::Instruction_t *checkEflags;
    inline static IRDB_SDK::Instruction_t *initGpRegisters;
    inline static IRDB_SDK::Instruction_t *enableLogging;
    inline static IRDB_SDK::Instruction_t *msan_set_keep_going;
    inline static IRDB_SDK::Instruction_t *msan_poison_stack;
    inline static IRDB_SDK::Instruction_t *isRegFullyDefined;
    inline static IRDB_SDK::Instruction_t *isMemFullyDefined;
    inline static IRDB_SDK::Instruction_t *isRegOrRegFullyDefined;
    inline static IRDB_SDK::Instruction_t *isRegOrMemFullyDefined;
    inline static IRDB_SDK::Instruction_t *setRflags;
    inline static IRDB_SDK::Instruction_t *setRegShadow;
    inline static IRDB_SDK::Instruction_t *setMemShadow;
    inline static IRDB_SDK::Instruction_t *unpoisonUpper4Bytes;
    inline static IRDB_SDK::Instruction_t *propagateRegOrRegShadow;
    inline static IRDB_SDK::Instruction_t *propagateRegOrMemShadow;
    inline static IRDB_SDK::Instruction_t *propagateMemOrRegShadow;
    inline static IRDB_SDK::Instruction_t *msan_check_mem_is_initialized;
};


#endif //BINARY_MSAN_RUNTIMELIB_H

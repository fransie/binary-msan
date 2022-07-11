#ifndef BINARY_MSAN_MEMORYACCESSINSTRUMENTATION_H
#define BINARY_MSAN_MEMORYACCESSINSTRUMENTATION_H

#include <irdb-core>
#include "CapstoneService.h"


class MemoryAccessInstrumentation {
public:
    static IRDB_SDK::Instruction_t* instrumentMemRef(const std::shared_ptr<IRDB_SDK::DecodedOperand_t> &operand,
                                                     IRDB_SDK::Instruction_t *instruction,
                                                     std::unique_ptr<CapstoneService> &capstoneService,
                                                     IRDB_SDK::FileIR_t *fileIr);
};


#endif //BINARY_MSAN_MEMORYACCESSINSTRUMENTATION_H

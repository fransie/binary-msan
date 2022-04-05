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
    MSan(IRDB_SDK::FileIR_t *p_variantIR);


    bool execute(IRDB_SDK::FileIR_t *);
    void reserveMemoryForRegisters();

public:
    std::vector<int64_t> shadowRegisters;
};

#endif

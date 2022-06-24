//
// Created by Franziska Mäckel on 07.04.22.
//

#ifndef BINARY_MSAN_INTERFACE_H
#define BINARY_MSAN_INTERFACE_H

#ifndef INTERFACE
    #define INTERFACE __attribute__((visibility ("default")))
#endif

#include <vector>
#include <bitset>
#include <memory>
#include <msan_interface_internal.h>
#include <iostream>
#include <msan.h>

// HIGHER_BYTE means, for example, register AH
enum WIDTH{
    QUAD_WORD = 64,
    DOUBLE_WORD = 32,
    WORD = 16,
    BYTE = 8,
    HIGHER_BYTE = 0
};

// mem access
INTERFACE void checkRegIsInit(int reg, int regWidth);

// mov
INTERFACE void defineRegShadow(int reg, int width);
INTERFACE void memToRegShadowCopy(int reg, int regWidth, __sanitizer::uptr memAddress);
INTERFACE void regToMemShadowCopy(int reg, int regWidth, __sanitizer::uptr memAddress);
INTERFACE void regToRegShadowCopy(int dest, int source, int width);

// test
INTERFACE void setFlagsAfterTest_Reg(int reg, int width);
INTERFACE void setFlagsAfterTest_RegReg(int destReg, int srcReg, int width);

// jump
INTERFACE void checkEflags();

// helpers
INTERFACE void initGpRegisters();
INTERFACE void disableHaltOnError();
void* getRegisterShadow(int reg, int regWidth);

#endif //BINARY_MSAN_INTERFACE_H
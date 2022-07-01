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
#include "../common/Width.h"

extern "C"{

// mem access
INTERFACE void checkRegIsInit(int reg, int regWidth);

// mov
INTERFACE void memToRegShadowCopy(int reg, int regWidth, __sanitizer::uptr memAddress);
INTERFACE void regToMemShadowCopy(int reg, int regWidth, __sanitizer::uptr memAddress);
INTERFACE void regToRegShadowCopy(int dest, int source, int width);

// jump
INTERFACE void checkEflags();

// helpers
INTERFACE void initGpRegisters();
void* getRegisterShadow(int reg, int regWidth);

bool isRegFullyDefined(int reg, int width);
bool isMemFullyDefined(const void *mem, uptr size);
bool isRegOrRegFullyDefined(int dest, int destWidth, int src, int srcWidth);
bool isRegOrMemFullyDefined(int reg, const void *mem, int width);

void setEflags(bool defined);

void setRegShadow(bool initState, int reg, int width);
void setMemShadow(bool initState, const void *mem, uptr size);

} // extern "C"
#endif //BINARY_MSAN_INTERFACE_H
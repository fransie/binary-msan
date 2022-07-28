#ifndef BINARY_MSAN_INTERFACE_H
#define BINARY_MSAN_INTERFACE_H

#ifndef INTERFACE
    #define INTERFACE __attribute__((visibility ("default")))
#endif

#include <bitset>
#include <msan.h>
#include <vector>

extern "C"{

extern std::vector<std::bitset<64>> shadowRegisterState;

// mem access
INTERFACE void checkRegIsInit(int reg, int regWidth);

// mov
INTERFACE void memToRegShadowCopy(__sanitizer::uptr memAddress, int reg, int regWidth);
INTERFACE void regToMemShadowCopy(__sanitizer::uptr memAddress, int reg, int regWidth);
INTERFACE void regToRegShadowCopy(int dest, int destWidth, int src, int srcWidth);
INTERFACE void unpoisonUpper4Bytes(int reg);

// eflags
INTERFACE void checkEflags();
INTERFACE void setEflags(bool shadow);

// helpers
INTERFACE void initGpRegisters();
INTERFACE void* getRegisterShadow(int reg, int regWidth);

INTERFACE bool isRegFullyDefined(int reg, int width);
INTERFACE bool isMemFullyDefined(const void *mem, uptr size);
INTERFACE bool isRegOrRegFullyDefined(int reg1, int reg1Width, int reg2, int reg2Width);
INTERFACE bool isRegOrMemFullyDefined(const void *mem, int reg, int width);

INTERFACE void propagateRegOrRegShadow(int dest, int destWidth, int src, int srcWidth);
INTERFACE void propagateRegOrMemShadow(const void *mem, int reg, int width);
INTERFACE void propagateMemOrRegShadow(const void *mem, int reg, int width);

INTERFACE void setRegShadow(bool isInited, int reg, int width);
INTERFACE void setMemShadow(const void *mem, bool initState, uptr size);

} // extern "C"
#endif //BINARY_MSAN_INTERFACE_H
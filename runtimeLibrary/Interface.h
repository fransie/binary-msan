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
INTERFACE void memToRegShadowCopy(int reg, int regWidth, __sanitizer::uptr memAddress);
INTERFACE void regToMemShadowCopy(int reg, int regWidth, __sanitizer::uptr memAddress);
INTERFACE void regToRegShadowCopy(const int dest, const int destWidth, const int src, const int srcWidth);
INTERFACE void initUpper4Bytes(const int reg);

// eflags
INTERFACE void checkEflags();
INTERFACE void setEflags(bool shadow);

// helpers
INTERFACE void initGpRegisters();
INTERFACE void* getRegisterShadow(int reg, int regWidth);

INTERFACE bool isRegFullyDefined(int reg, int width);
INTERFACE bool isMemFullyDefined(const void *mem, uptr size);
INTERFACE bool isRegOrRegFullyDefined(int dest, int destWidth, int src, int srcWidth);
INTERFACE bool isRegOrMemFullyDefined(int reg, const void *mem, int width);

INTERFACE void propagateRegOrRegShadow(int dest, int destWidth, int src, int srcWidth);
INTERFACE void propagateRegOrMemShadow(int reg, const void *mem, int width);
INTERFACE void propagateMemOrRegShadow(int reg, const void *mem, int width);

INTERFACE void setRegShadow(bool isInited, int reg, int width);
INTERFACE void setMemShadow(bool initState, const void *mem, uptr size);

} // extern "C"
#endif //BINARY_MSAN_INTERFACE_H
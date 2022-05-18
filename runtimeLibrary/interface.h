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

// HIGHER_BYTE means, for example, register AH
enum WIDTH{
    QUAD_WORD = 64,
    DOUBLE_WORD = 32,
    WORD = 16,
    BYTE = 8,
    HIGHER_BYTE = 0
};



INTERFACE void regToRegShadowCopy(int dest, int source, int width);
INTERFACE void defineRegShadow(int reg, int width);
INTERFACE void checkRegIsInit(int reg, int regWidth);



#endif //BINARY_MSAN_INTERFACE_H
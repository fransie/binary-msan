//
// Created by Franziska Mäckel on 07.04.22.
//

#ifndef BINARY_MSAN_INTERFACE_H
#define BINARY_MSAN_INTERFACE_H

#ifndef INTERFACE
    #define INTERFACE __attribute__((visibility ("default")))
#endif

#include <iostream>
#include <vector>


INTERFACE void regToRegShadowCopy(int dest, int source);
INTERFACE void defineRegShadow(int reg);




#endif //BINARY_MSAN_INTERFACE_H
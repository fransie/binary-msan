//
// Created by Franziska Mäckel on 07.04.22.
//

#ifndef BINARY_MSAN_INTERFACE_H
#define BINARY_MSAN_INTERFACE_H

#ifndef INTERFACE
    #define INTERFACE __attribute__((visibility ("default")))
#endif


class MSanInterface{
    INTERFACE void testing();
    INTERFACE void regToRegMove(int dest, int source);
};


#endif //BINARY_MSAN_INTERFACE_H
//
// Created by Franziska Mäckel on 07.04.22.
//

#ifndef BINARY_MSAN_INTERFACE_H
#define BINARY_MSAN_INTERFACE_H

#ifndef INTERFACE
    #define INTERFACE __attribute__((visibility ("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

INTERFACE void testing();

#ifdef __cplusplus
} // closing brace for "extern C"
#endif

#endif //BINARY_MSAN_INTERFACE_H
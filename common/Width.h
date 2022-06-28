//
// Created by Franziska Mäckel on 12.06.22.
//

#ifndef BINARY_MSAN_WIDTH_H
#define BINARY_MSAN_WIDTH_H

// HIGHER_BYTE means, for example, register AH
enum WIDTH{
    QUAD_WORD = 64,
    DOUBLE_WORD = 32,
    WORD = 16,
    BYTE = 8,
    HIGHER_BYTE = 0
};


#endif //BINARY_MSAN_WIDTH_H

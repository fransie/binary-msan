#ifndef BINARY_MSAN_WIDTH_H
#define BINARY_MSAN_WIDTH_H

/**
 * Register or memory location sizes in bits. HIGHER_BYTE means, for example, register AH.
 */
enum WIDTH{
    QUAD_WORD = 64,
    DOUBLE_WORD = 32,
    WORD = 16,
    BYTE = 8,
    HIGHER_BYTE = 0
};

#endif //BINARY_MSAN_WIDTH_H

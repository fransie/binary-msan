#ifndef BINARY_MSAN_REGISTERNUMBERING_H
#define BINARY_MSAN_REGISTERNUMBERING_H
/**
 * Contains the numbering that zipr uses as well (see file operand_csx86.cpp) for more readable
 * usage in binary-msan code.
 */
enum RegisterNumbering{
    RAX = 0,
    RCX = 1,
    RDX = 2,
    RSP = 4,
    RBP = 5,
    RSI = 6,
    RDI = 7,
    R8 = 8,
    R9 = 9,
    R10 = 10,
    R11 = 11,
    R12 = 12,
    R13 = 13,
    R14 = 14,
    R15 = 15
};

#endif //BINARY_MSAN_REGISTERNUMBERING_H
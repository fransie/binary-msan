// COMPILE-OPTIONS: -ggdb

#include <iostream>

int main() {
    uint64_t a = 8;
    if (a == 8)
        return 0;
    return 2;
}

// EXPECTED: Check manually for the exit code of this program: ./obj/stack_leaf_values_not_overwritten_sanitized && echo $? - should be 0.
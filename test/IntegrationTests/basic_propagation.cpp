#include <iostream>

int main() {
    uint64_t a = 5;
    uint64_t b;
    a = a + b;
    if (a)
        printf("xx\n");
    return 0;
}

// EXPECTED: MemorySanitizer: use-of-uninitialized-value
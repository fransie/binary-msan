#include <iostream>

int main() {
    uint64_t a;
    if (a)
        printf("xx\n");
    return 0;
}

// EXPECTED: MemorySanitizer: use-of-uninitialized-value
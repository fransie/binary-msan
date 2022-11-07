#include <iostream>

int main() {
    printf("This should be printed.\n");
    uint64_t a = 5;
    uint64_t b;
    a = a - b;
    if (a)
        printf("This should not be printed.\n");
    return 0;
}

// EXPECTED: MemorySanitizer: use-of-uninitialized-value
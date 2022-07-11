#include <iostream>

int main(int argc, char** argv) {
    uint64_t a;
    if (a)
        return 1;
    return 0;
}

// EXPECTED: MemorySanitizer: use-of-uninitialized-value
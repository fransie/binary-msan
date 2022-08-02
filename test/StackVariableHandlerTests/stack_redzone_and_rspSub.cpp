#include <iostream>

int main() {
    // 17 * 8 byte -> more than fits into 128-byte red zone
    uint64_t array[17];
    for (int i = 1; i <= 16; i++){
        array[i] = 2;
    }
    if (array[0])
        return 1;
    return 0;
}

// EXPECTED: MemorySanitizer: use-of-uninitialized-value
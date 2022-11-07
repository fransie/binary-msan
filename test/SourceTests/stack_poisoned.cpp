// BINMSAN COMPILE OPTIONS

#include <iostream>
#include <cassert>
#include "../../src/runtimeLibrary/BinMsanApi.h"

int main() {
    uint64_t a;

    auto shadow = reinterpret_cast<uint64_t*>((unsigned long long)(&a) ^ 0x500000000000ULL);
    assert(*shadow == UINT64_MAX);

    std::cout << "Success.";
    return 0;
}

// EXPECTED: Success.
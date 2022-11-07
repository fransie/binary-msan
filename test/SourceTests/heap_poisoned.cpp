// BINMSAN COMPILE OPTIONS

#include <iostream>
#include <cassert>
#include "../../src/runtimeLibrary/BinMsanApi.h"
#include "../../src/common/RegisterNumbering.h"

int main() {
    // define rax here because "new" is not instrumented yet and returns an uninit address in rax, which is wrong.
    setRegShadow(true,RAX,64);
    uint64_t *ptr = new uint64_t;

    auto shadow = reinterpret_cast<uint64_t*>((unsigned long long)(ptr) ^ 0x500000000000ULL);
    assert(*shadow == UINT64_MAX);

    std::cout << "Success.";
    return 0;
}

// EXPECTED: Success.
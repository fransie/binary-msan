// BINMSAN COMPILE OPTIONS

#include <unistd.h>
#include <iostream>
#include "../../src/runtimeLibrary/BinMsanApi.h"
#include "../../src/common/RegisterNumbering.h"

int main() {
    // define rax here because "new" is not instrumented yet and returns an uninit address in rax, which is wrong.
    setRegShadow(true,RAX,64);
    char *ptr = new char[10];
    std::cout << ptr << std::endl;
    return 0;
}

// EXPECTED: MemorySanitizer: use-of-uninitialized-value
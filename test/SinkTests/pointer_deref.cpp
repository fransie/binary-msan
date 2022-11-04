// BINMSAN COMPILE OPTIONS


#include "../../src/runtimeLibrary/BinMsanApi.h"
#include "../../src/common/RegisterNumbering.h"

int main(int argc, char** argv) {
    // define rax here because "new" is not instrumented yet and returns an uninit address in rax, which is wrong.
    setRegShadow(true,RAX,64);
    int **ptr = (int **) new int;
    int number = **ptr;
    return 0;
}

// EXPECTED: MemorySanitizer: use-of-uninitialized-value
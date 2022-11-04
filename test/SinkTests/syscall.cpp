// BINMSAN COMPILE OPTIONS


#include <unistd.h>
#include "../../src/runtimeLibrary/BinMsanApi.h"
#include "../../src/common/RegisterNumbering.h"

int main() {
    // define rax here because "new" is not instrumented yet and returns an uninit address in rax, which is wrong.
    setRegShadow(true,RAX,64);
    char *ptr = new char;
    write(1, ptr, 1);
    return 0;
}

// EXPECTED: MemorySanitizer: use-of-uninitialized-value
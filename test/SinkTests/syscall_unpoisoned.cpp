// BINMSAN COMPILE OPTIONS


#include <unistd.h>
#include "../../src/runtimeLibrary/BinMsanApi.h"
#include "../../src/common/RegisterNumbering.h"

int main() {
    // define rax here because "new" is not instrumented yet and returns an uninit address in rax, which is wrong.
    setRegShadow(true,RAX,64);
    char *ptr = new char[]{'S','u','c','c','e','s','s','.'};
    write(1, ptr, 8);
    return 0;
}

// EXPECTED: Success.
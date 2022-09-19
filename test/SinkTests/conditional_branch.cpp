// COMPILE OPTIONS: -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/lib/msan -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/include/sanitizer/ -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/lib/  -L$BINMSAN_HOME/plugins_install -linterface


#include <stdio.h>
#include "../../src/runtimeLibrary/BinMsanApi.h"
#include "../../src/common/RegisterNumbering.h"

int main(int argc, char** argv) {
    // define rax here because "new" is not instrumented yet and returns an uninit address in rax, which in wrong.
    setRegShadow(true,RAX,64);
    int *a = new int[10];
    a[5] = 0;
    if (a[argc])
        printf("xx\n");
    return 0;
}

// EXPECTED: MemorySanitizer: use-of-uninitialized-value
// COMPILE OPTIONS: -I/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/lib/msan -I/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/include/sanitizer/ -I/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/lib/  -L/home/franzi/Documents/binary-msan/plugins_install -linterface

#include <stdio.h>
#include "../runtimeLibrary/Interface.h"

int main(int argc, char** argv) {
    // define rax here because "new" is not instrumented yet and returns an uninit address in rax, which in wrong.
    setRegShadow(true,0,64);
    int *a = new int[10];
    a[5] = 0;
    if (a[argc])
        printf("xx\n");
    return 0;
}

// EXPECTED: MemorySanitizer: use-of-uninitialized-value
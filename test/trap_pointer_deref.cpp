// COMPILE OPTIONS: -I/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/lib/msan -I/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/include/sanitizer/ -I/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/lib/  -L/home/franzi/Documents/binary-msan/plugins_install -linterface

#include <iostream>
#include "../runtimeLibrary/Interface.h"

int main(int argc, char** argv) {
    // define rax here because "new" is not instrumented yet and returns an uninit address in rax, which is wrong.
    defineRegShadow(0,64);
    int **ptr = (int **) new int;
    int number = **ptr;
    return 0;
}

// EXPECTED: MemorySanitizer: use-of-uninitialized-value
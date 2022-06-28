// COMPILE OPTIONS: -I/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/lib/msan -I/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/include/sanitizer/ -I/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/lib/  -L/home/franzi/Documents/binary-msan/plugins_install -linterface

#include "../runtimeLibrary/Interface.h"

int main(int argc, char** argv) {
    // given
    defineRegShadow(0,64);
    uint64_t *a = new uint64_t;
    checkRegIsInit(0,64);

    // when
    asm( "mov %0, %%rax" : : "m" (*a));

    // then this should lead to a warning
    checkRegIsInit(0,QUAD_WORD);
    return 0;
}

// EXPECTED: MemorySanitizer: use-of-uninitialized-value

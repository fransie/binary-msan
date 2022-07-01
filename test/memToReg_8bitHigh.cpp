// COMPILE OPTIONS: -I/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/lib/msan -I/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/include/sanitizer/ -I/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/lib/  -L/home/franzi/Documents/binary-msan/plugins_install -linterface

#include "../runtimeLibrary/Interface.h"

int main(int argc, char** argv) {
    // given
    setRegShadow(0,0,0,64);
    uint8_t *a = new uint8_t;
    checkRegIsInit(0,64);

    // when
    asm( "mov %0, %%ah" : : "m" (*a));

    // then this should be uninit
    checkRegIsInit(0,HIGHER_BYTE);
    return 0;
}

// EXPECTED: MemorySanitizer: use-of-uninitialized-value

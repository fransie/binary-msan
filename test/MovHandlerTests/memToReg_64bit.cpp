// COMPILE OPTIONS: -I/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/lib/msan -I/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/include/sanitizer/ -I/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/lib/  -L/home/franzi/Documents/binary-msan/plugins_install -linterface

#include "../../runtimeLibrary/Interface.h"
#include "../../common/RegisterNumbering.h"

int main(int argc, char** argv) {
    // given
    setRegShadow(true,RAX,64);
    uint64_t *a = new uint64_t;
    checkRegIsInit(RAX,64);

    // when
    asm( "mov %0, %%rax" : : "m" (*a));

    // then this should lead to a warning
    checkRegIsInit(RAX,QUAD_WORD);
    return 0;
}

// EXPECTED: MemorySanitizer: use-of-uninitialized-value

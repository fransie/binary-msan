// BINMSAN COMPILE OPTIONS


#include "../../src/runtimeLibrary/BinMsanApi.h"
#include "../../src/common/RegisterNumbering.h"
#include "../../src/common/Width.h"

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

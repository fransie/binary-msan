// BINMSAN COMPILE OPTIONS


#include "../../src/runtimeLibrary/BinMsanApi.h"
#include "../../src/common/RegisterNumbering.h"
#include "../../src/common/Width.h"

int main() {
    // given
    setRegShadow(true,RAX,64);
    uint32_t *a = new uint32_t;
    checkRegIsInit(RAX,64);

    // when
    asm( "mov %0, %%eax" : : "m" (*a));

    // then this should be uninit
    checkRegIsInit(RAX,DOUBLE_WORD);
    return 0;
}

// EXPECTED: MemorySanitizer: use-of-uninitialized-value

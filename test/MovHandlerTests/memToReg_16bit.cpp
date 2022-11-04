// BINMSAN COMPILE OPTIONS


#include "../../src/runtimeLibrary/BinMsanApi.h"
#include "../../src/common/RegisterNumbering.h"
#include "../../src/common/Width.h"

int main(int argc, char** argv) {
    // given
    setRegShadow(true,RAX,64);
    uint16_t *a = new uint16_t;
    checkRegIsInit(RAX,64);

    // when
    asm( "mov %0, %%ax" : : "m" (*a));

    // then this should be uninit
    checkRegIsInit(RAX,WORD);
    return 0;
}

// EXPECTED: MemorySanitizer: use-of-uninitialized-value

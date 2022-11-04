// BINMSAN COMPILE OPTIONS


#include "../../src/runtimeLibrary/BinMsanApi.h"
#include "../../src/common/RegisterNumbering.h"
#include "../../src/common/Width.h"

int main(int argc, char** argv) {
    // given
    setRegShadow(true,RAX,64);
    uint8_t *a = new uint8_t;
    checkRegIsInit(RAX,64);

    // when
    asm( "mov %0, %%ah" : : "m" (*a));

    // then this should be uninit
    checkRegIsInit(RAX,HIGHER_BYTE);
    return 0;
}

// EXPECTED: MemorySanitizer: use-of-uninitialized-value

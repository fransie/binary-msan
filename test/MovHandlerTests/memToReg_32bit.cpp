// BINMSAN COMPILE OPTIONS

#include <iostream>
#include <cassert>
#include "../../src/runtimeLibrary/BinMsanApi.h"
#include "../../src/common/RegisterNumbering.h"
#include "../../src/common/Width.h"

int main() {
    // given
    uint32_t *a = new uint32_t;
    shadowRegisterState[R10] = std::bitset<64>{0x0000000000000000};

    // when
    asm( "mov %0, %%r10d" : : "m" (*a));

    // then
    assert(shadowRegisterState[R10].to_ullong() == 0x00000000ffffffff);
    std::cout << "Success." << std::endl;
    return 0;
}

// EXPECTED: Success.
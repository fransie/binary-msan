// BINMSAN COMPILE OPTIONS

#include <iostream>
#include <cassert>
#include "../../src/runtimeLibrary/BinMsanApi.h"
#include "../../src/common/RegisterNumbering.h"
#include "../../src/common/Width.h"

int main(int argc, char** argv) {
    // given
    uint16_t *a = new uint16_t;
    shadowRegisterState[R10] = std::bitset<64>{0x0000000000000000};

    // when
    asm( "mov %0, %%r10w" : : "m" (*a));

    // then
    assert(shadowRegisterState[R10].to_ullong() == 0x000000000000ffff);
    std::cout << "Success." << std::endl;
    return 0;
}

// EXPECTED: Success.

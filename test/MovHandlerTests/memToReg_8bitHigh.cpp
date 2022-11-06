// BINMSAN COMPILE OPTIONS

#include <iostream>
#include <cassert>
#include "../../src/runtimeLibrary/BinMsanApi.h"
#include "../../src/common/RegisterNumbering.h"

int main(int argc, char** argv) {
    // given
    shadowRegisterState[RBX] = std::bitset<64>{0x0000000000000000};
    uint8_t *a = new uint8_t;

    // when
    asm( "mov %0, %%bh" : : "m" (*a));

    // then
    assert(shadowRegisterState[RBX].to_ullong() == 0x000000000000ff00);
    std::cout << "Success." << std::endl;
    return 0;
}

// EXPECTED: Success.

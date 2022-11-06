// BINMSAN COMPILE OPTIONS

#include <iostream>
#include <cassert>
#include "../../src/runtimeLibrary/BinMsanApi.h"
#include "../../src/common/RegisterNumbering.h"
#include "../../src/common/Width.h"

int main(int argc, char** argv) {
    // given
    shadowRegisterState[R10] = std::bitset<64>{0x0000000000000000};
    uint8_t *a = new uint8_t;

    // when
    asm( "mov %0, %%r10b" : : "m" (*a));

    // then
    assert(shadowRegisterState[R10].to_ullong() == 0x00000000000000ff);
    std::cout << "Success." << std::endl;
    return 0;
}

// EXPECTED: Success.

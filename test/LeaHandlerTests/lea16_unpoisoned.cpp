// BINMSAN COMPILE OPTIONS


#include <cassert>
#include <iostream>
#include "../../src/runtimeLibrary/BinMsanApi.h"
#include "../../src/common/RegisterNumbering.h"

int main() {
    // given
    shadowRegisterState[R10] = std::bitset<64>{0x0000000000000000};
    shadowRegisterState[R11] = std::bitset<64>{0x0000000000000000};
    shadowRegisterState[R12] = std::bitset<64>{0x000f000000000000};

    // when
    asm ("lea (%r11d,%r12d), %r10w");

    // then
    assert(shadowRegisterState[R10].to_ullong() == 0);
    std::cout << "Success." << std::endl;
    return 0;
}

// EXPECTED: Success.
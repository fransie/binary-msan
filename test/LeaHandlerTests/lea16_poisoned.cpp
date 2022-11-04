// BINMSAN COMPILE OPTIONS


#include <cassert>
#include <iostream>
#include "../../src/runtimeLibrary/BinMsanApi.h"
#include "../../src/common/RegisterNumbering.h"

int main() {
    // given
    shadowRegisterState[R10] = std::bitset<64>{0xa000000000000000};
    shadowRegisterState[R11] = std::bitset<64>{0x000f0000000000ff};

    // when
    asm ("lea (%r11), %r10w");

    // then
    assert(shadowRegisterState[R10].to_ullong() == 0xa00000000000ffff);
    std::cout << "Success." << std::endl;
    return 0;
}

// EXPECTED: Success.
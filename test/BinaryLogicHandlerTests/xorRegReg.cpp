// BINMSAN COMPILE OPTIONS


#include <cassert>
#include <iostream>
#include "../../src/runtimeLibrary/BinMsanApi.h"
#include "../../src/common/RegisterNumbering.h"

int main() {
    // given
    shadowRegisterState[R10] = std::bitset<64>{0x00ff00ff00ff00ff};

    // when
    asm ("xor %r10, %r10");

    // then
    assert(shadowRegisterState[R10].to_ullong() == 0);
    std::cout << "Success." << std::endl;
    return 0;
}

// EXPECTED: Success.
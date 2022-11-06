// BINMSAN COMPILE OPTIONS


#include <assert.h>
#include <iostream>
#include <cstdint>
#include "../../src/runtimeLibrary/BinMsanApi.h"
#include "../../src/common/RegisterNumbering.h"

int main() {
    // given
    shadowRegisterState[R10] = std::bitset<64>{0x0000000000000000};;
    shadowRegisterState[R11] = std::bitset<64>{0xffffffffffffffff};

    // when
    asm ("mov %r10d, %r11d");

    // then
    assert(shadowRegisterState[R11].to_ullong() == 0);
    std::cout << "Success." << std::endl;
    return 0;
}

// EXPECTED: Success.
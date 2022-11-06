// BINMSAN COMPILE OPTIONS


#include <assert.h>
#include <iostream>
#include <cstdint>
#include "../../src/runtimeLibrary/BinMsanApi.h"
#include "../../src/common/RegisterNumbering.h"

int main() {
    // given
    shadowRegisterState[RBX] = std::bitset<64>{0x0000000000000000};
    shadowRegisterState[RCX] = std::bitset<64>{0xffffffffffffffff};

    // when
    asm ("mov %bh, %ch");

    // then
    assert(shadowRegisterState[RCX].to_ullong() == 0xffffffffffff00ff);
    std::cout << "Success." << std::endl;
    return 0;
}

// EXPECTED: Success.
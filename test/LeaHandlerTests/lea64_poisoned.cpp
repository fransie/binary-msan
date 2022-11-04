// BINMSAN COMPILE OPTIONS


#include <cassert>
#include <iostream>
#include "../../src/runtimeLibrary/BinMsanApi.h"
#include "../../src/common/RegisterNumbering.h"

int main() {
    // given
    shadowRegisterState[RSI] = std::bitset<64>{0x0000000000000000};
    shadowRegisterState[RBX] = std::bitset<64>{0x00000000000000f0};
    shadowRegisterState[RAX] = std::bitset<64>{0x0000000000000000};

    // when
    asm ("lea (%esi,%ebx), %rax");

    // then
    assert(shadowRegisterState[RAX].to_ullong() == UINT64_MAX);
    std::cout << "Success." << std::endl;
    return 0;
}

// EXPECTED: Success.
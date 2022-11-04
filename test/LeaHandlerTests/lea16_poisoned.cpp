// BINMSAN COMPILE OPTIONS


#include <cassert>
#include <iostream>
#include "../../src/runtimeLibrary/BinMsanApi.h"
#include "../../src/common/RegisterNumbering.h"

int main() {
    // given
    shadowRegisterState[RBX] = std::bitset<64>{0x000f0000000000f0};
    shadowRegisterState[RAX] = std::bitset<64>{0xa000000000000000};

    // when
    asm ("lea (%ebx), %ax");

    // then
    std::cout << shadowRegisterState[RAX].to_ullong() << std::endl;
    assert(shadowRegisterState[RAX].to_ullong() == 0xa00000000000ffff);
    std::cout << "Success." << std::endl;
    return 0;
}

// EXPECTED: Success.
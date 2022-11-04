// BINMSAN COMPILE OPTIONS


#include <cassert>
#include <iostream>
#include "../../src/runtimeLibrary/BinMsanApi.h"
#include "../../src/common/RegisterNumbering.h"

int main() {
    // given
    shadowRegisterState[RAX] = std::bitset<64>{0x00ff00ff00ff00ff};
    assert(shadowRegisterState[RAX].to_ullong() == 0x00ff00ff00ff00ff);

    // when
    asm ("and $5, %rax");

    // then
    assert(shadowRegisterState[RAX].to_ullong() == 0x00ff00ff00ff00ff);
    std::cout << "Success." << std::endl;
    return 0;
}

// EXPECTED: Success.
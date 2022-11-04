// BINMSAN COMPILE OPTIONS


#include <cassert>
#include <iostream>
#include "../../src/runtimeLibrary/BinMsanApi.h"
#include "../../src/common/RegisterNumbering.h"

int main() {
    // given
    assert(shadowRegisterState[RAX].to_ullong() == UINT64_MAX);

    // when
    asm ("mov $5, %eax");

    // then
    std::cout << shadowRegisterState[RAX].to_ullong() << std::endl;
    assert(shadowRegisterState[RAX].to_ullong() == 0x0000000000000000);
    std::cout << "Success." << std::endl;
    return 0;
}

// EXPECTED: Success.
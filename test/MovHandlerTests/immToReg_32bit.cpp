// BINMSAN COMPILE OPTIONS


#include <cassert>
#include <iostream>
#include "../../src/runtimeLibrary/BinMsanApi.h"
#include "../../src/common/RegisterNumbering.h"

int main() {
    // given
    assert(shadowRegisterState[R10].to_ullong() == UINT64_MAX);

    // when
    asm ("mov $5, %r10d");

    // then
    assert(shadowRegisterState[R10].to_ullong() == 0x0000000000000000);
    std::cout << "Success." << std::endl;
    return 0;
}

// EXPECTED: Success.
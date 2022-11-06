// BINMSAN COMPILE OPTIONS


#include <cassert>
#include <iostream>
#include "../../src/runtimeLibrary/BinMsanApi.h"
#include "../../src/common/RegisterNumbering.h"


int main() {
    // given
    assert(shadowRegisterState[RBX].to_ullong() == UINT64_MAX);

    // when
    asm ("mov $5, %bh");

    // then
    assert(shadowRegisterState[RBX].to_ullong() == 0xffffffffffff00ff);
    std::cout << "Success." << std::endl;
    return 0;
}

// EXPECTED: Success.
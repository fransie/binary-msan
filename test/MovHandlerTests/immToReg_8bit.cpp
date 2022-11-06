// BINMSAN COMPILE OPTIONS


#include <cassert>
#include <iostream>
#include "../../src/runtimeLibrary/BinMsanApi.h"
#include "../../src/common/RegisterNumbering.h"

int main() {
    // given
    assert(shadowRegisterState[R10].to_ullong() == UINT64_MAX);

    // when
    asm ("movb $5, %r10b");

    // then
    assert(shadowRegisterState[R10].to_ullong() == 0xffffffffffffff00);
    std::cout << "Success." << std::endl;
    return 0;
}

// EXPECTED: Success.
// BINMSAN COMPILE OPTIONS


#include <cassert>
#include <iostream>
#include "../../src/runtimeLibrary/BinMsanApi.h"
#include "../../src/common/RegisterNumbering.h"

int main() {
    // given
    assert(shadowRegisterState[RAX].to_ullong() == UINT64_MAX);

    // when
    asm ("movb $5, %al");

    // then
    assert(shadowRegisterState[RAX].to_ullong() == 0xffffffffffffff00);
    std::cout << "Success." << std::endl;
    return 0;
}

// EXPECTED: Success.
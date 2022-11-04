// BINMSAN COMPILE OPTIONS


#include <assert.h>
#include <iostream>
#include <cstdint>
#include "../../src/runtimeLibrary/BinMsanApi.h"
#include "../../src/common/RegisterNumbering.h"

int main() {
    // given
    // define rax here because "new" is not instrumented yet and returns an uninit address is rax, which is wrong.
    setRegShadow(true,RAX,64);
    assert(shadowRegisterState[RAX].to_ullong() == 0);
    assert(shadowRegisterState[RCX].to_ullong() == UINT64_MAX);

    // when
    asm ("mov %al, %ch");

    // then
    assert(shadowRegisterState[RCX].to_ullong() == 0xffffffffffff00ff);
    std::cout << "Success." << std::endl;
    return 0;
}

// EXPECTED: Success.
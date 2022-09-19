// COMPILE OPTIONS: -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/lib/msan -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/include/sanitizer/ -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/lib/  -L$BINMSAN_HOME/plugins_install -linterface


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
    asm ("mov %ax, %cx");

    // then
    assert(shadowRegisterState[RCX].to_ullong() == 0xffffffffffff0000);
    std::cout << "Success." << std::endl;
    return 0;
}

// EXPECTED: Success.
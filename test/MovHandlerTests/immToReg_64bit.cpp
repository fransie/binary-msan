// COMPILE OPTIONS: -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/lib/msan -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/include/sanitizer/ -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/lib/  -L$BINMSAN_HOME/plugins_install -lbinmsan_lib


#include <cassert>
#include <iostream>
#include "../../src/runtimeLibrary/BinMsanApi.h"
#include "../../src/common/RegisterNumbering.h"

int main() {
    // given
    assert(shadowRegisterState[RAX].to_ullong() == UINT64_MAX);

    // when
    asm ("mov $5, %rax");

    // then
    std::cout << shadowRegisterState[RAX].to_ullong() << std::endl;
    assert(shadowRegisterState[RAX].to_ullong() == 0x0000000000000000);
    std::cout << "Success." << std::endl;
    return 0;
}

// EXPECTED: Success.
// COMPILE OPTIONS: -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/lib/msan -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/include/sanitizer/ -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/lib/  -L$BINMSAN_HOME/plugins_install -lbinmsan_lib


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
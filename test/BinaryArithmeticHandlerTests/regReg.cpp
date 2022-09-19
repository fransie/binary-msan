// COMPILE OPTIONS: -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/lib/msan -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/include/sanitizer/ -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/lib/  -L$BINMSAN_HOME/plugins_install -linterface


#include <cassert>
#include <iostream>
#include "../../src/runtimeLibrary/BinMsanApi.h"
#include "../../src/common/RegisterNumbering.h"

int main() {
    // given
    shadowRegisterState[RCX] = std::bitset<64>{0xff00ff00ff00ff00};
    shadowRegisterState[RAX] = std::bitset<64>{0x0000000000000000};

    // when
    asm ("add %rax, %rcx");

    // then
    assert(shadowRegisterState[RAX].to_ullong() == 0x0000000000000000);
    assert(shadowRegisterState[RCX].to_ullong() == 0xffffffffffffffff);
    std::cout << "Success." << std::endl;
    return 0;
}

// EXPECTED: Success.
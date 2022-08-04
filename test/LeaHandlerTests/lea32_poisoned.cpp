// COMPILE OPTIONS: -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/lib/msan -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/include/sanitizer/ -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/lib/  -L$BINMSAN_HOME/plugins_install -linterface


#include <cassert>
#include <iostream>
#include "../../runtimeLibrary/Interface.h"
#include "../../common/RegisterNumbering.h"

int main() {
    // given
    shadowRegisterState[RSI] = std::bitset<64>{0x0000000000000000};
    shadowRegisterState[RBX] = std::bitset<64>{0x000f0000000000f0};
    shadowRegisterState[RAX] = std::bitset<64>{0x0000000000000000};

    // when
    asm ("lea (%esi,%ebx), %eax");

    // then
    assert(shadowRegisterState[RAX].to_ullong() == 0x00000000ffffffff);
    std::cout << "Success." << std::endl;
    return 0;
}

// EXPECTED: Success.
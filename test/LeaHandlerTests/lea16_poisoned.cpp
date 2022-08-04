// COMPILE OPTIONS: -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/lib/msan -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/include/sanitizer/ -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/lib/  -L$BINMSAN_HOME/plugins_install -linterface


#include <cassert>
#include <iostream>
#include "../../runtimeLibrary/Interface.h"
#include "../../common/RegisterNumbering.h"

int main() {
    // given
    shadowRegisterState[RBX] = std::bitset<64>{0x000f0000000000f0};
    shadowRegisterState[RAX] = std::bitset<64>{0xa000000000000000};

    // when
    asm ("lea (%ebx), %ax");

    // then
    std::cout << shadowRegisterState[RAX].to_ullong() << std::endl;
    assert(shadowRegisterState[RAX].to_ullong() == 0xa00000000000ffff);
    std::cout << "Success." << std::endl;
    return 0;
}

// EXPECTED: Success.
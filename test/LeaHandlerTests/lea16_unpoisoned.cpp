// COMPILE OPTIONS: -I/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/lib/msan -I/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/include/sanitizer/ -I/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/lib/  -L/home/franzi/Documents/binary-msan/plugins_install -linterface

#include <cassert>
#include <iostream>
#include "../../runtimeLibrary/Interface.h"
#include "../../common/RegisterNumbering.h"

int main() {
    // given
    shadowRegisterState[RSI] = std::bitset<64>{0x0000000000000000};
    shadowRegisterState[RBX] = std::bitset<64>{0x000f000000000000};
    shadowRegisterState[RAX] = std::bitset<64>{0x0000000000000000};

    // when
    asm ("lea (%esi,%ebx), %ax");

    // then
    assert(shadowRegisterState[RAX].to_ullong() == 0);
    std::cout << "Success." << std::endl;
    return 0;
}

// EXPECTED: Success.
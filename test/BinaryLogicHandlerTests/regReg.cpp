// COMPILE OPTIONS: -I/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/lib/msan -I/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/include/sanitizer/ -I/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/lib/  -L/home/franzi/Documents/binary-msan/plugins_install -linterface

#include <cassert>
#include <iostream>
#include "../../runtimeLibrary/Interface.h"
#include "../../common/RegisterNumbering.h"

int main() {
    // given
    shadowRegisterState[RCX] = std::bitset<64>{0xff00ff00ff00ff00};
    shadowRegisterState[RAX] = std::bitset<64>{0x00ff00ff00ff00ff};

    // when
    asm ("and %rax, %rcx");

    // then
    assert(shadowRegisterState[RAX].to_ullong() == 0x00ff00ff00ff00ff);
    assert(shadowRegisterState[RCX].to_ullong() == 0xffffffffffffffff);
    std::cout << "Success." << std::endl;
    return 0;
}

// EXPECTED: Success.
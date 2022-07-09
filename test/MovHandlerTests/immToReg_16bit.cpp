// COMPILE OPTIONS: -I/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/lib/msan -I/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/include/sanitizer/ -I/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/lib/  -L/home/franzi/Documents/binary-msan/plugins_install -linterface

#include <cassert>
#include <iostream>
#include "../../runtimeLibrary/Interface.h"

int main() {
    // given
    assert(shadowRegisterState[0].to_ullong() == UINT64_MAX);

    // when
    asm ("mov $5, %ax");

    // then
    std::cout << shadowRegisterState[0].to_ullong() << std::endl;
    assert(shadowRegisterState[0].to_ullong() == 0xffffffffffff0000);
    std::cout << "Success." << std::endl;
    return 0;
}

// EXPECTED: Success.
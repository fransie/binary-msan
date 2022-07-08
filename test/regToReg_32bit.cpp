// COMPILE OPTIONS: -I/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/lib/msan -I/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/include/sanitizer/ -I/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/lib/  -L/home/franzi/Documents/binary-msan/plugins_install -linterface

#include <assert.h>
#include <iostream>
#include <cstdint>
#include "../runtimeLibrary/Interface.h"

int main() {
    // given
    // define rax here because "new" is not instrumented yet and returns an uninit address is rax, which is wrong.
    setRegShadow(true,0,64);
    assert(shadowRegisterState[0].to_ullong() == 0);
    assert(shadowRegisterState[1].to_ullong() == UINT64_MAX);

    // when
    asm ("mov %eax, %ecx");

    // then
    assert(shadowRegisterState[1].to_ullong() == 0);
    std::cout << "Success." << std::endl;
    return 0;
}

// EXPECTED: Success.
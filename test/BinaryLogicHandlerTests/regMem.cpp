// COMPILE OPTIONS: -I/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/lib/msan -I/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/include/sanitizer/ -I/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/lib/  -L/home/franzi/Documents/binary-msan/plugins_install -linterface

#include <cassert>
#include <iostream>
#include "../../runtimeLibrary/Interface.h"
#include "../../common/RegisterNumbering.h"

int main() {
    // given
    shadowRegisterState[RAX] = std::bitset<64>{0x00a00000000000ff};
    uint64_t *a = new uint64_t{5};

    // when
    asm ("and %0, %%rax" : "=m" ( *a ));

    // then
    assert(shadowRegisterState[RAX].to_ullong() == 0x00a00000000000ff);
    std::cout << "Success." << std::endl;
    return 0;
}

// EXPECTED: Success.
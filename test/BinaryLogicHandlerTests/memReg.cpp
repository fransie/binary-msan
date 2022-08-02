// COMPILE OPTIONS: -I/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/lib/msan -I/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/include/sanitizer/ -I/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/lib/  -L/home/franzi/Documents/binary-msan/plugins_install -linterface

#include <cassert>
#include <iostream>
#include "../../runtimeLibrary/Interface.h"
#include "../../common/RegisterNumbering.h"

void testShadow0(uint64_t *ptr){
    auto shadow = reinterpret_cast<uint64_t*>((unsigned long long)(ptr) ^ 0x500000000000ULL);
    assert(*shadow == 0);
    std::cout << "Success." << std::endl;
}

void testShadowNot0(uint64_t *ptr){
    auto shadow = reinterpret_cast<uint64_t*>((unsigned long long)(ptr) ^ 0x500000000000ULL);
    assert(*shadow == 0x000000000000000f);
}

int main() {
    // given
    uint64_t *a = new uint64_t{5};
    testShadow0(a);
    shadowRegisterState[RAX] = std::bitset<64>{0x000000000000000f};

    // when
    asm ("and %%rax, %0" : "=m" ( *a ));

    // then
    testShadowNot0(a);
    std::cout << "Success." << std::endl;
    return 0;
}

// EXPECTED: Success.
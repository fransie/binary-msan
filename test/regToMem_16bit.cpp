// COMPILE OPTIONS: -I/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/lib/msan -I/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/include/sanitizer/ -I/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/lib/  -L/home/franzi/Documents/binary-msan/plugins_install -linterface

#include <assert.h>
#include <iostream>
#include <cstdint>
#include "../runtimeLibrary/Interface.h"


void testShadowNot0(u_int16_t *ptr){
    auto shadow = reinterpret_cast<uint16_t*>((unsigned long long)(ptr) ^ 0x500000000000ULL);
    assert(*shadow == UINT16_MAX);
}

void testShadow0(u_int16_t *ptr){
    auto shadow = reinterpret_cast<uint16_t*>((unsigned long long)(ptr) ^ 0x500000000000ULL);
    assert(*shadow == 0);
    std::cout << "Success." << std::endl;
}

int main() {
    // define rax here because "new" is not instrumented yet and returns an uninit address in rax, which is wrong.
    defineRegShadow(0,64);
    u_int16_t *a = new u_int16_t;
    testShadowNot0(a);
    asm ("mov $1, %rax");
    asm ("mov %%ax, %0" : "=m" ( *a ));
    testShadow0(a);
    return 0;
}

// EXPECTED: Success.
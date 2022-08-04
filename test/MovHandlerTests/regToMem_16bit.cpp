// COMPILE OPTIONS: -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/lib/msan -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/include/sanitizer/ -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/lib/  -L$BINMSAN_HOME/plugins_install -linterface


#include <assert.h>
#include <iostream>
#include <cstdint>
#include "../../runtimeLibrary/Interface.h"
#include "../../common/RegisterNumbering.h"


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
    setRegShadow(true,RAX,64);
    u_int16_t *a = new u_int16_t;
    testShadowNot0(a);
    asm ("mov $1, %rax");
    asm ("mov %%ax, %0" : "=m" ( *a ));
    testShadow0(a);
    return 0;
}

// EXPECTED: Success.
// COMPILE OPTIONS: -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/lib/msan -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/include/sanitizer/ -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/lib/  -L$BINMSAN_HOME/plugins_install -lbinmsan_lib


#include <assert.h>
#include <iostream>
#include <cstdint>
#include "../../src/runtimeLibrary/BinMsanApi.h"
#include "../../src/common/RegisterNumbering.h"

void testShadowNot0(u_int8_t *ptr){
    auto shadow = reinterpret_cast<uint8_t*>((unsigned long long)(ptr) ^ 0x500000000000ULL);
    assert(*shadow == UINT8_MAX);
}

void testShadow0(u_int8_t *ptr){
    auto shadow = reinterpret_cast<uint8_t*>((unsigned long long)(ptr) ^ 0x500000000000ULL);
    assert(*shadow == 0);
    std::cout << "Success." << std::endl;
}

int main() {
    // define rax here because "new" is not instrumented yet and returns an uninit address is rax, which is wrong.
    setRegShadow(true,RAX,64);
    u_int8_t *a = new u_int8_t;
    testShadowNot0(a);
    asm ("mov $1, %rax");
    asm ("mov %%al, %0" : "=m" ( *a ));
    testShadow0(a);
    return 0;
}

// EXPECTED: Success.
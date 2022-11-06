// BINMSAN COMPILE OPTIONS


#include <assert.h>
#include <iostream>
#include <cstdint>
#include "../../src/runtimeLibrary/BinMsanApi.h"
#include "../../src/common/RegisterNumbering.h"

void testShadowNot0(u_int32_t *ptr){
    auto shadow = reinterpret_cast<uint32_t*>((unsigned long long)(ptr) ^ 0x500000000000ULL);
    assert(*shadow == UINT32_MAX);
}

void testShadow0(u_int32_t *ptr){
    auto shadow = reinterpret_cast<uint32_t*>((unsigned long long)(ptr) ^ 0x500000000000ULL);
    assert(*shadow == 0);
    std::cout << "Success." << std::endl;
}

int main() {
    // define rax here because "new" is not instrumented yet and returns an uninit address is rax, which is wrong.
    setRegShadow(true,RAX,64);
    u_int32_t *a = new u_int32_t;
    testShadowNot0(a);
    asm ("mov $1, %r10");
    asm ("mov %%r10d, %0" : "=m" ( *a ));
    testShadow0(a);
    return 0;
}

// EXPECTED: Success.
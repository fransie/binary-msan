// COMPILE OPTIONS: -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/lib/msan -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/include/sanitizer/ -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/lib/  -L$BINMSAN_HOME/plugins_install -linterface


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
    assert(*shadow == UINT64_MAX);
}

int main() {
    // given
    uint64_t *a = new uint64_t{5};
    testShadow0(a);
    shadowRegisterState[RAX] = std::bitset<64>{0xffffffffffffffff};

    // when
    asm ("add %%rax, %0" : "=m" ( *a ));

    // then
    testShadowNot0(a);
    std::cout << "Success." << std::endl;
    return 0;
}

// EXPECTED: Success.
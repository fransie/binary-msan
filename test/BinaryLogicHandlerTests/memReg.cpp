// BINMSAN COMPILE OPTIONS


#include <cassert>
#include <iostream>
#include "../../src/runtimeLibrary/BinMsanApi.h"
#include "../../src/common/RegisterNumbering.h"

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
    shadowRegisterState[R10] = std::bitset<64>{0x000000000000000f};

    // when
    asm ("and %%r10, %0" : "=m" ( *a ));

    // then
    testShadowNot0(a);
    std::cout << "Success." << std::endl;
    return 0;
}

// EXPECTED: Success.
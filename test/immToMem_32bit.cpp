#include <assert.h>
#include <iostream>

void testShadowNot0(uint32_t *ptr){
    auto shadow = reinterpret_cast<uint32_t*>((unsigned long long)(ptr) ^ 0x500000000000ULL);
    assert(*shadow == UINT32_MAX);
}

void testShadow0(uint32_t *ptr){
    auto shadow = reinterpret_cast<uint32_t*>((unsigned long long)(ptr) ^ 0x500000000000ULL);
    assert(*shadow == 0);
    std::cout << "Success." << std::endl;
}

int main() {
    // given
    uint32_t *a = new uint32_t;
    testShadowNot0(a);

    // when
    asm ("movl $5, %0" : "=m" ( *a ));

    // then
    testShadow0(a);
    return 0;
}

// EXPECTED: Success.
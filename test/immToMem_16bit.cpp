#include <assert.h>
#include <iostream>

void testShadowNot0(uint16_t *ptr){
    auto shadow = reinterpret_cast<uint16_t*>((unsigned long long)(ptr) ^ 0x500000000000ULL);
    assert(*shadow == UINT16_MAX);
}

void testShadow0(uint16_t *ptr){
    auto shadow = reinterpret_cast<uint16_t*>((unsigned long long)(ptr) ^ 0x500000000000ULL);
    assert(*shadow == 0);
    std::cout << "Success." << std::endl;
}

int main() {
    // given
    uint16_t *a = new uint16_t;
    testShadowNot0(a);

    // when
    asm ("movw $5, %0" : "=m" ( *a ));

    // then
    testShadow0(a);
    return 0;
}

// EXPECTED: Success.
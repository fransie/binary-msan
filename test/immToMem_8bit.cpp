#include <assert.h>
#include <iostream>

void testShadowNot0(uint8_t *ptr){
    auto shadow = reinterpret_cast<uint8_t*>((unsigned long long)(ptr) ^ 0x500000000000ULL);
    assert(*shadow == UINT8_MAX);
}

void testShadow0(uint8_t *ptr){
    auto shadow = reinterpret_cast<uint8_t*>((unsigned long long)(ptr) ^ 0x500000000000ULL);
    assert(*shadow == 0);
    std::cout << "Success." << std::endl;
}

int main() {
    // given
    uint8_t *a = new uint8_t;
    testShadowNot0(a);

    // when
    asm ("movb $5, %0" : "=m" ( *a ));

    // then
    testShadow0(a);
    return 0;
}

// EXPECTED: Success.
#include <assert.h>
#include <iostream>

void testShadowNot0(uint64_t *ptr){
    auto shadow = reinterpret_cast<uint64_t*>((unsigned long long)(ptr) ^ 0x500000000000ULL);
    assert(*shadow == UINT64_MAX);
}

void testShadow0(uint64_t *ptr){
    auto shadow = reinterpret_cast<uint64_t*>((unsigned long long)(ptr) ^ 0x500000000000ULL);
    assert(*shadow == 0);
    std::cout << "Success." << std::endl;
}

int main() {
    // given
    uint64_t *a = new uint64_t;
    testShadowNot0(a);

    // when
    asm ("movq $5, %0" : "=m" ( *a ));

    // then
    testShadow0(a);
    return 0;
}

// EXPECTED: Success.
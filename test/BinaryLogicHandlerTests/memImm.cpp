#include <cassert>
#include <iostream>

void testShadowNot0(uint64_t *ptr){
    auto shadow = reinterpret_cast<uint64_t*>((unsigned long long)(ptr) ^ 0x500000000000ULL);
    assert(*shadow == UINT64_MAX);
}

int main() {
    // given
    uint64_t *a = new uint64_t;
    testShadowNot0(a);

    // when
    asm ("and $5, %0" : "=m" ( *a ));

    // then
    testShadowNot0(a);
    std::cout << "Success." << std::endl;
    return 0;
}

// EXPECTED: Success.
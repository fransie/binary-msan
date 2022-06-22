#include <assert.h>


void testShadow(long long *ptr){
    auto shadow = reinterpret_cast<long long*>((unsigned long long)(&ptr) ^ 0x500000000000ULL);
    assert(*shadow == 0);
}

int main(int argc, char** argv) {
    long long a;
    asm ("mov $1, %rax");
    asm ("mov %%rax, %0" : "=r" ( a ));
    testShadow(&a);
    return 0;
}

// EXPECTED: memToRegShadowCopy. Shadow of reg 0 is: 0xffffffffffffffff.
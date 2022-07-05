#include <cassert>
#include <iostream>
#include <msan.h>
#include "gtest/gtest.h"
#include "../runtimeLibrary/Interface.h"

TEST(ImmToMemTestsuite, Eight){
    // given
    __msan_init();
    auto *a = new uint8_t;
    auto shadow = reinterpret_cast<uint8_t*>((unsigned long long)(a) ^ 0x500000000000ULL);
    EXPECT_EQ(*shadow, UINT8_MAX);

    // when
    setMemShadow(1, a, 1);

    // then
    shadow = reinterpret_cast<uint8_t*>((unsigned long long)(a) ^ 0x500000000000ULL);
    EXPECT_EQ(*shadow, 0);
}

//
//void testShadowNot0(uint8_t *ptr){
//    auto shadow = reinterpret_cast<uint8_t*>((unsigned long long)(ptr) ^ 0x500000000000ULL);
//    assert(*shadow == UINT8_MAX);
//}
//
//void testShadow0(uint8_t *ptr){
//    auto shadow = reinterpret_cast<uint8_t*>((unsigned long long)(ptr) ^ 0x500000000000ULL);
//    assert(*shadow == 0);
//    std::cout << "Success." << std::endl;
//}
//
//int main() {
//    // given
//    uint8_t *a = new uint8_t;
//    testShadowNot0(a);
//
//    // when
//    asm ("movb $5, %0" : "=m" ( *a ));
//
//    // then
//    testShadow0(a);
//    return 0;
//}


        //given
//        __msan_set_keep_going(1);
//        auto *a = new uint64_t;
//        *a = 8;
//        auto shadow = new int64_t;
//        *shadow = 5;
////        auto shadow = reinterpret_cast<uint8_t*>((unsigned long long)(a) ^ 0x500000000000ULL);
//        BOOST_REQUIRE_EQUAL(*shadow, UINT8_MAX);
//
//        // when
//        asm ("movb $5, %0" : "=m" ( *a ));
//
//        // then
////        shadow = reinterpret_cast<uint8_t*>((unsigned long long)(a) ^ 0x500000000000ULL);


// EXPECTED: Success.
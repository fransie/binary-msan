#include <cassert>
#include <iostream>
#include <msan.h>
#include "gtest/gtest.h"
#include "../runtimeLibrary/Interface.h"

TEST(setMemShadowTests, UnpoisonBits8){
    // given
    auto *a = new uint8_t;
    auto shadow = reinterpret_cast<uint8_t*>((unsigned long long)(a) ^ 0x500000000000ULL);
    EXPECT_EQ(*shadow, UINT8_MAX);

    // when
    setMemShadow(1, a, 1);

    // then
    shadow = reinterpret_cast<uint8_t*>((unsigned long long)(a) ^ 0x500000000000ULL);
    EXPECT_EQ(*shadow, 0);
}

TEST(setMemShadowTests, UnpoisonBits16){
    // given
    auto *a = new uint16_t;
    auto shadow = reinterpret_cast<uint16_t*>((unsigned long long)(a) ^ 0x500000000000ULL);
    EXPECT_EQ(*shadow, UINT16_MAX);

    // when
    setMemShadow(1, a, 2);

    // then
    shadow = reinterpret_cast<uint16_t*>((unsigned long long)(a) ^ 0x500000000000ULL);
    EXPECT_EQ(*shadow, 0);
}

TEST(setMemShadowTests, UnpoisonBits32){
    // given
    auto *a = new u_int32_t ;
    auto shadow = reinterpret_cast<u_int32_t*>((unsigned long long)(a) ^ 0x500000000000ULL);
    EXPECT_EQ(*shadow, UINT32_MAX);

    // when
    setMemShadow(1, a, 4);

    // then
    shadow = reinterpret_cast<u_int32_t*>((unsigned long long)(a) ^ 0x500000000000ULL);
    EXPECT_EQ(*shadow, 0);
}

TEST(setMemShadowTests, UnpoisonBits64){
    // given
    auto *a = new uint64_t;
    auto shadow = reinterpret_cast<uint64_t*>((unsigned long long)(a) ^ 0x500000000000ULL);
    EXPECT_EQ(*shadow, UINT64_MAX);

    // when
    setMemShadow(1, a, 8);

    // then
    shadow = reinterpret_cast<uint64_t*>((unsigned long long)(a) ^ 0x500000000000ULL);
    EXPECT_EQ(*shadow, 0);
}

TEST(setMemShadowTests, PoisonBits8){
    // given
    auto *a = new uint8_t;
    auto shadow = reinterpret_cast<uint8_t*>((unsigned long long)(a) ^ 0x500000000000ULL);
    EXPECT_EQ(*shadow, UINT8_MAX);

    // when
    setMemShadow(0, a, 1);

    // then
    shadow = reinterpret_cast<uint8_t*>((unsigned long long)(a) ^ 0x500000000000ULL);
    EXPECT_EQ(*shadow, UINT8_MAX);
}

TEST(setMemShadowTests, PoisonBits16){
    // given
    auto *a = new uint16_t;
    auto shadow = reinterpret_cast<uint16_t*>((unsigned long long)(a) ^ 0x500000000000ULL);
    EXPECT_EQ(*shadow, UINT16_MAX);

    // when
    setMemShadow(0, a, 2);

    // then
    shadow = reinterpret_cast<uint16_t*>((unsigned long long)(a) ^ 0x500000000000ULL);
    EXPECT_EQ(*shadow, UINT16_MAX);
}

TEST(setMemShadowTests, PoisonBits32){
    // given
    auto *a = new u_int32_t ;
    auto shadow = reinterpret_cast<u_int32_t*>((unsigned long long)(a) ^ 0x500000000000ULL);
    EXPECT_EQ(*shadow, UINT32_MAX);

    // when
    setMemShadow(0, a, 4);

    // then
    shadow = reinterpret_cast<u_int32_t*>((unsigned long long)(a) ^ 0x500000000000ULL);
    EXPECT_EQ(*shadow, UINT32_MAX);
}

TEST(setMemShadowTests, PoisonBits64){
    // given
    auto *a = new uint64_t;
    auto shadow = reinterpret_cast<uint64_t*>((unsigned long long)(a) ^ 0x500000000000ULL);
    EXPECT_EQ(*shadow, UINT64_MAX);

    // when
    setMemShadow(0, a, 8);

    // then
    shadow = reinterpret_cast<uint64_t*>((unsigned long long)(a) ^ 0x500000000000ULL);
    EXPECT_EQ(*shadow, UINT64_MAX);
}
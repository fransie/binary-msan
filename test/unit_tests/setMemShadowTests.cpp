#include <iostream>
#include <msan.h>
#include "gtest/gtest.h"
#include "../../runtimeLibrary/Interface.h"

TEST(setMemShadowTests, UnpoisonBits8){
    // given
    auto *a = new uint8_t;
    auto shadow = reinterpret_cast<uint8_t*>(MEM_TO_SHADOW(a));
    EXPECT_EQ(*shadow, UINT8_MAX);

    // when
    setMemShadow(a, true, 1);

    // then
    shadow = reinterpret_cast<uint8_t*>(MEM_TO_SHADOW(a));
    EXPECT_EQ(*shadow, 0);
}

TEST(setMemShadowTests, UnpoisonBits16){
    // given
    auto *a = new uint16_t;
    auto shadow = reinterpret_cast<uint16_t*>(MEM_TO_SHADOW(a));
    EXPECT_EQ(*shadow, UINT16_MAX);

    // when
    setMemShadow(a, true, 2);

    // then
    shadow = reinterpret_cast<uint16_t*>(MEM_TO_SHADOW(a));
    EXPECT_EQ(*shadow, 0);
}

TEST(setMemShadowTests, UnpoisonBits32){
    // given
    auto *a = new u_int32_t ;
    auto shadow = reinterpret_cast<u_int32_t*>(MEM_TO_SHADOW(a));
    EXPECT_EQ(*shadow, UINT32_MAX);

    // when
    setMemShadow(a, true, 4);

    // then
    shadow = reinterpret_cast<u_int32_t*>(MEM_TO_SHADOW(a));
    EXPECT_EQ(*shadow, 0);
}

TEST(setMemShadowTests, UnpoisonBits64){
    // given
    auto *a = new uint64_t;
    auto shadow = reinterpret_cast<uint64_t*>(MEM_TO_SHADOW(a));
    EXPECT_EQ(*shadow, UINT64_MAX);

    // when
    setMemShadow(a, true, 8);

    // then
    shadow = reinterpret_cast<uint64_t*>(MEM_TO_SHADOW(a));
    EXPECT_EQ(*shadow, 0);
}

// TODO: fix these tests
/**
 * ##############################################################################
 * For some weird reason I don't know, I cannot write these tests like this:
 *
 * TEST(setMemShadowTests, PoisonBits8){
    // given
    auto *a = new uint8_t{12};
    auto shadow = reinterpret_cast<uint8_t*>(MEM_TO_SHADOW(a));
    EXPECT_EQ(*shadow, 0);

    // when
    setMemShadow(false, a, 1);

    // then
    shadow = reinterpret_cast<uint8_t*>(MEM_TO_SHADOW(a));
    EXPECT_EQ(*shadow, UINT8_MAX);
}
 * It fails since memory sanitizer complain about shadow being uninitialised. Oh well, it does not make sense
 * to test this since it's not application memory! I don't know why it works above.
 */

TEST(setMemShadowTests, PoisonBits8){
    // given
    auto *a = new uint8_t{12};
    EXPECT_EQ(isMemFullyDefined(a, 1), true);

    // when
    setMemShadow(a, false, 1);

    // then
    EXPECT_EQ(isMemFullyDefined(a, 1), false);
}

TEST(setMemShadowTests, PoisonBits16){
    // given
    auto *a = new uint16_t{12};
    EXPECT_EQ(isMemFullyDefined(a, 2), true);

    // when
    setMemShadow(a, false, 2);

    // then
    EXPECT_EQ(isMemFullyDefined(a, 2), false);
}

TEST(setMemShadowTests, PoisonBits32){
    // given
    auto *a = new u_int32_t{12};
    EXPECT_EQ(isMemFullyDefined(a, 4), true);

    // when
    setMemShadow(a, false, 4);

    // then
    EXPECT_EQ(isMemFullyDefined(a, 4), false);
}

TEST(setMemShadowTests, PoisonBits64){
    // given
    auto *a = new uint64_t{12};
    EXPECT_EQ(isMemFullyDefined(a, 8), true);

    // when
    setMemShadow(a, false, 8);

    // then
    EXPECT_EQ(isMemFullyDefined(a, 8), false);
}
#include <cassert>
#include <iostream>
#include <msan.h>
#include "gtest/gtest.h"
#include "../../runtimeLibrary/Interface.h"
#include "../../common/RegisterNumbering.h"
#include "../../common/Width.h"

TEST(setRegShadowTests, UnpoisonBits8){
    // given
    shadowRegisterState[RAX].set();
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), UINT64_MAX);

    // when
    setRegShadow(true, RAX, BYTE);

    // then
    auto regShadow = shadowRegisterState[RAX].to_ullong();
    EXPECT_EQ(regShadow, 0xffffffffffffff00);
}

TEST(setRegShadowTests, UnpoisonBits8High){
    // given
    shadowRegisterState[RAX].set();
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), UINT64_MAX);

    // when
    setRegShadow(true, RAX, HIGHER_BYTE);

    // then
    auto regShadow = shadowRegisterState[RAX].to_ullong();
    EXPECT_EQ(regShadow, 0xffffffffffff00ff);
}

TEST(setRegShadowTests, UnpoisonBits16){
    // given
    shadowRegisterState[RAX].set();
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), UINT64_MAX);

    // when
    setRegShadow(true, RAX, WORD);

    // then
    auto regShadow = shadowRegisterState[RAX].to_ullong();
    EXPECT_EQ(regShadow, 0xffffffffffff0000);
}

TEST(setRegShadowTests, UnpoisonBits32){
    // given
    shadowRegisterState[RAX].set();
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), UINT64_MAX);

    // when
    setRegShadow(true, RAX, DOUBLE_WORD);

    // then
    auto regShadow = shadowRegisterState[RAX].to_ullong();
    EXPECT_EQ(regShadow, 0xffffffff00000000);
}

TEST(setRegShadowTests, UnpoisonBits64){
    // given
    shadowRegisterState[RAX].set();
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), UINT64_MAX);

    // when
    setRegShadow(true, RAX, QUAD_WORD);

    // then
    auto regShadow = shadowRegisterState[RAX].to_ullong();
    EXPECT_EQ(regShadow, 0x0000000000000000);
}

TEST(setRegShadowTests, PoisonBits8){
    // given
    shadowRegisterState[RAX].reset();
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0);

    // when
    setRegShadow(false, RAX, BYTE);

    // then
    auto regShadow = shadowRegisterState[RAX].to_ullong();
    EXPECT_EQ(regShadow, 0x0000000000000000ff);
}

TEST(setRegShadowTests, PoisonBits8High){
    // given
    shadowRegisterState[RAX].reset();
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0);

    // when
    setRegShadow(false, RAX, HIGHER_BYTE);

    // then
    auto regShadow = shadowRegisterState[RAX].to_ullong();
    EXPECT_EQ(regShadow, 0x00000000000000ff00);
}

TEST(setRegShadowTests, PoisonBits16){
    // given
    shadowRegisterState[RAX].reset();
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0);

    // when
    setRegShadow(false, RAX, WORD);

    // then
    auto regShadow = shadowRegisterState[RAX].to_ullong();
    EXPECT_EQ(regShadow, 0x000000000000ffff);
}

TEST(setRegShadowTests, PoisonBits32){
    // given
    shadowRegisterState[RAX].reset();
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0);

    // when
    setRegShadow(false, RAX, DOUBLE_WORD);

    // then
    auto regShadow = shadowRegisterState[RAX].to_ullong();
    EXPECT_EQ(regShadow, 0x00000000ffffffff);
}

TEST(setRegShadowTests, PoisonBits64){
    // given
    shadowRegisterState[RAX].reset();
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0);

    // when
    setRegShadow(false, RAX, QUAD_WORD);

    // then
    auto regShadow = shadowRegisterState[RAX].to_ullong();
    EXPECT_EQ(regShadow, 0xffffffffffffffff);
}

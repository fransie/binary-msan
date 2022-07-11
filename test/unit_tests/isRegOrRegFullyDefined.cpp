#include <iostream>
#include <msan.h>
#include "gtest/gtest.h"
#include "../../runtimeLibrary/Interface.h"
#include "../../common/RegisterNumbering.h"

TEST(isRegOrRegFullyDefinedTests, bothFullyDefined){
    // given
    shadowRegisterState[RAX].reset();
    shadowRegisterState[RCX].reset();
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0);
    EXPECT_EQ(shadowRegisterState[RCX].to_ullong(), 0);

    // when
    auto result = isRegOrRegFullyDefined(RAX,QUAD_WORD, RCX, QUAD_WORD);

    // then
    EXPECT_EQ(result, true);
}

TEST(isRegOrRegFullyDefinedTests, bothFullyUndefined){
    // given
    shadowRegisterState[RAX].set();
    shadowRegisterState[RCX].set();
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), UINT64_MAX);
    EXPECT_EQ(shadowRegisterState[RCX].to_ullong(), UINT64_MAX);

    // when
    auto result = isRegOrRegFullyDefined(RAX,QUAD_WORD, RCX, QUAD_WORD);

    // then
    EXPECT_EQ(result, false);
}

TEST(isRegOrRegFullyDefinedTests, oneFullyUndefined){
    // given
    shadowRegisterState[RAX].set();
    shadowRegisterState[RCX].reset();
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), UINT64_MAX);
    EXPECT_EQ(shadowRegisterState[RCX].to_ullong(), 0);

    // when
    auto result = isRegOrRegFullyDefined(RAX,QUAD_WORD, RCX, QUAD_WORD);

    // then
    EXPECT_EQ(result, false);
}

TEST(isRegOrRegFullyDefinedTests, oneUndefined32){
    // given
    shadowRegisterState[RAX].reset();
    shadowRegisterState[RCX].reset();
    shadowRegisterState[RCX].set(8, true);
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0);
    EXPECT_EQ(shadowRegisterState[RCX].to_ullong(), 0x100);

    // when
    auto result = isRegOrRegFullyDefined(RAX,DOUBLE_WORD, RCX, DOUBLE_WORD);

    // then
    EXPECT_EQ(result, false);
}

TEST(isRegOrRegFullyDefinedTests, oneUndefined8High){
    // given
    shadowRegisterState[RAX].reset();
    shadowRegisterState[RCX].reset();
    shadowRegisterState[RCX].set(8, true);
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0);
    EXPECT_EQ(shadowRegisterState[RCX].to_ullong(), 0x100);

    // when
    auto result = isRegOrRegFullyDefined(RAX,HIGHER_BYTE, RCX, HIGHER_BYTE);

    // then
    EXPECT_EQ(result, false);
}

#include <iostream>
#include <msan.h>
#include "gtest/gtest.h"
#include "../../runtimeLibrary/Interface.h"

TEST(isRegOrRegFullyDefinedTests, bothFullyDefined){
    // given
    shadowRegisterState[0].reset();
    shadowRegisterState[1].reset();
    EXPECT_EQ(shadowRegisterState[0].to_ullong(), 0);
    EXPECT_EQ(shadowRegisterState[1].to_ullong(), 0);

    // when
    auto result = isRegOrRegFullyDefined(0,QUAD_WORD, 1, QUAD_WORD);

    // then
    EXPECT_EQ(result, true);
}

TEST(isRegOrRegFullyDefinedTests, bothFullyUndefined){
    // given
    shadowRegisterState[0].set();
    shadowRegisterState[1].set();
    EXPECT_EQ(shadowRegisterState[0].to_ullong(), UINT64_MAX);
    EXPECT_EQ(shadowRegisterState[1].to_ullong(), UINT64_MAX);

    // when
    auto result = isRegOrRegFullyDefined(0,QUAD_WORD, 1, QUAD_WORD);

    // then
    EXPECT_EQ(result, false);
}

TEST(isRegOrRegFullyDefinedTests, oneFullyUndefined){
    // given
    shadowRegisterState[0].set();
    shadowRegisterState[1].reset();
    EXPECT_EQ(shadowRegisterState[0].to_ullong(), UINT64_MAX);
    EXPECT_EQ(shadowRegisterState[1].to_ullong(), 0);

    // when
    auto result = isRegOrRegFullyDefined(0,QUAD_WORD, 1, QUAD_WORD);

    // then
    EXPECT_EQ(result, false);
}

TEST(isRegOrRegFullyDefinedTests, oneUndefined32){
    // given
    shadowRegisterState[0].reset();
    shadowRegisterState[1].reset();
    shadowRegisterState[1].set(8, true);
    EXPECT_EQ(shadowRegisterState[0].to_ullong(), 0);
    EXPECT_EQ(shadowRegisterState[1].to_ullong(), 0x100);

    // when
    auto result = isRegOrRegFullyDefined(0,DOUBLE_WORD, 1, DOUBLE_WORD);

    // then
    EXPECT_EQ(result, false);
}

TEST(isRegOrRegFullyDefinedTests, oneUndefined8High){
    // given
    shadowRegisterState[0].reset();
    shadowRegisterState[1].reset();
    shadowRegisterState[1].set(8, true);
    EXPECT_EQ(shadowRegisterState[0].to_ullong(), 0);
    EXPECT_EQ(shadowRegisterState[1].to_ullong(), 0x100);

    // when
    auto result = isRegOrRegFullyDefined(0,HIGHER_BYTE, 1, HIGHER_BYTE);

    // then
    EXPECT_EQ(result, false);
}

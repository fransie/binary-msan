#include <iostream>
#include <msan.h>
#include "gtest/gtest.h"
#include "../../runtimeLibrary/Interface.h"

TEST(isRegOrMemFullyDefinedTests, bothFullyDefined){
    // given
    shadowRegisterState[0].reset();
    auto *a = new uint64_t {12};
    EXPECT_EQ(shadowRegisterState[0].to_ullong(), 0);

    // when
    auto result = isRegOrMemFullyDefined(0, a, QUAD_WORD);

    // then
    EXPECT_EQ(result, true);
}

TEST(isRegOrMemFullyDefinedTests, bothFullyUndefined){
    // given
    shadowRegisterState[0].set();
    auto *a = new uint64_t;
    EXPECT_EQ(shadowRegisterState[0].to_ullong(), UINT64_MAX);

    // when
    auto result = isRegOrMemFullyDefined(0, a, QUAD_WORD);

    // then
    EXPECT_EQ(result, false);
}

TEST(isRegOrMemFullyDefinedTests, regFullyUndefined){
    // given
    shadowRegisterState[0].set();
    auto *a = new uint64_t {12};
    EXPECT_EQ(shadowRegisterState[0].to_ullong(), UINT64_MAX);

    // when
    auto result = isRegOrMemFullyDefined(0, a, QUAD_WORD);

    // then
    EXPECT_EQ(result, false);
}

TEST(isRegOrMemFullyDefinedTests, regUndefined8High){
    // given
    shadowRegisterState[0].reset();
    shadowRegisterState[0].set(8,true);
    auto *a = new uint64_t {12};
    EXPECT_EQ(shadowRegisterState[0].to_ullong(), 0x100);

    // when
    auto result = isRegOrMemFullyDefined(0, a, HIGHER_BYTE);

    // then
    EXPECT_EQ(result, false);
}

TEST(isRegOrMemFullyDefinedTests, memFullyUndefined){
    // given
    shadowRegisterState[0].reset();
    auto *a = new uint64_t;
    EXPECT_EQ(shadowRegisterState[0].to_ullong(), 0);

    // when
    auto result = isRegOrMemFullyDefined(0, a, QUAD_WORD);

    // then
    EXPECT_EQ(result, false);
}

TEST(isRegOrMemFullyDefinedTests, memUndefined8High){
    // given
    shadowRegisterState[0].reset();
    auto *a = new uint64_t;
    EXPECT_EQ(shadowRegisterState[0].to_ullong(), 0);

    // when
    auto result = isRegOrMemFullyDefined(0, a, HIGHER_BYTE);

    // then
    EXPECT_EQ(result, false);
}

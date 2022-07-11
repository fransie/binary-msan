#include <iostream>
#include <msan.h>
#include "gtest/gtest.h"
#include "../../runtimeLibrary/Interface.h"
#include "../../common/RegisterNumbering.h"

TEST(isRegOrMemFullyDefinedTests, bothFullyDefined){
    // given
    shadowRegisterState[RAX].reset();
    auto *a = new uint64_t {12};
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0);

    // when
    auto result = isRegOrMemFullyDefined(RAX, a, QUAD_WORD);

    // then
    EXPECT_EQ(result, true);
}

TEST(isRegOrMemFullyDefinedTests, bothFullyUndefined){
    // given
    shadowRegisterState[RAX].set();
    auto *a = new uint64_t;
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), UINT64_MAX);

    // when
    auto result = isRegOrMemFullyDefined(RAX, a, QUAD_WORD);

    // then
    EXPECT_EQ(result, false);
}

TEST(isRegOrMemFullyDefinedTests, regFullyUndefined){
    // given
    shadowRegisterState[RAX].set();
    auto *a = new uint64_t {12};
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), UINT64_MAX);

    // when
    auto result = isRegOrMemFullyDefined(RAX, a, QUAD_WORD);

    // then
    EXPECT_EQ(result, false);
}

TEST(isRegOrMemFullyDefinedTests, regUndefined8High){
    // given
    shadowRegisterState[RAX].reset();
    shadowRegisterState[RAX].set(8,true);
    auto *a = new uint64_t {12};
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0x100);

    // when
    auto result = isRegOrMemFullyDefined(RAX, a, HIGHER_BYTE);

    // then
    EXPECT_EQ(result, false);
}

TEST(isRegOrMemFullyDefinedTests, memFullyUndefined){
    // given
    shadowRegisterState[RAX].reset();
    auto *a = new uint64_t;
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0);

    // when
    auto result = isRegOrMemFullyDefined(RAX, a, QUAD_WORD);

    // then
    EXPECT_EQ(result, false);
}

TEST(isRegOrMemFullyDefinedTests, memUndefined8High){
    // given
    shadowRegisterState[RAX].reset();
    auto *a = new uint64_t;
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0);

    // when
    auto result = isRegOrMemFullyDefined(RAX, a, HIGHER_BYTE);

    // then
    EXPECT_EQ(result, false);
}

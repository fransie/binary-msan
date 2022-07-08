#include <cassert>
#include <iostream>
#include <msan.h>
#include "gtest/gtest.h"
#include "../../runtimeLibrary/Interface.h"

TEST(isRegFullyDefinedTests, fullyDefined){
    // given
    shadowRegisterState[0].reset();
    EXPECT_EQ(shadowRegisterState[0].to_ullong(), 0);

    // when
    auto result = isRegFullyDefined(0,QUAD_WORD);

    // then
    EXPECT_EQ(result, true);
}

TEST(isRegFullyDefinedTests, fullyUndefined){
    // given
    shadowRegisterState[0].set();
    EXPECT_EQ(shadowRegisterState[0].to_ullong(), UINT64_MAX);

    // when
    auto result = isRegFullyDefined(0,QUAD_WORD);

    // then
    EXPECT_EQ(result, false);
}

TEST(isRegFullyDefinedTests, undefined8High){
    // given
    shadowRegisterState[0].reset();
    shadowRegisterState[0].set(8,true);
    EXPECT_EQ(shadowRegisterState[0].to_ullong(), 0x0000000000000100);

    // when
    auto result = isRegFullyDefined(0,HIGHER_BYTE);

    // then
    EXPECT_EQ(result, false);
}

TEST(isRegFullyDefinedTests, undefinedButInIrrelevantArea32){
    // given
    shadowRegisterState[0].reset();
    shadowRegisterState[0].set(63,true);
    EXPECT_EQ(shadowRegisterState[0].to_ullong(), 0x8000000000000000);

    // when
    auto result = isRegFullyDefined(0,DOUBLE_WORD);

    // then
    EXPECT_EQ(result, true);
}

TEST(isRegFullyDefinedTests, undefinedButInIrrelevantArea8High){
    // given
    shadowRegisterState[0].reset();
    shadowRegisterState[0].set(0,true);
    EXPECT_EQ(shadowRegisterState[0].to_ullong(), 0x0000000000000001);

    // when
    auto result = isRegFullyDefined(0,HIGHER_BYTE);

    // then
    EXPECT_EQ(result, true);
}
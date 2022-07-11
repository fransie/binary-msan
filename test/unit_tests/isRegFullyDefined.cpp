#include <cassert>
#include <iostream>
#include <msan.h>
#include "gtest/gtest.h"
#include "../../runtimeLibrary/Interface.h"
#include "../../common/RegisterNumbering.h"

TEST(isRegFullyDefinedTests, fullyDefined){
    // given
    shadowRegisterState[RAX].reset();
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0);

    // when
    auto result = isRegFullyDefined(RAX,QUAD_WORD);

    // then
    EXPECT_EQ(result, true);
}

TEST(isRegFullyDefinedTests, fullyUndefined){
    // given
    shadowRegisterState[RAX].set();
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), UINT64_MAX);

    // when
    auto result = isRegFullyDefined(RAX,QUAD_WORD);

    // then
    EXPECT_EQ(result, false);
}

TEST(isRegFullyDefinedTests, undefined8High){
    // given
    shadowRegisterState[RAX].reset();
    shadowRegisterState[RAX].set(8,true);
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0x0000000000000100);

    // when
    auto result = isRegFullyDefined(RAX,HIGHER_BYTE);

    // then
    EXPECT_EQ(result, false);
}

TEST(isRegFullyDefinedTests, undefinedButInIrrelevantArea32){
    // given
    shadowRegisterState[RAX].reset();
    shadowRegisterState[RAX].set(63,true);
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0x8000000000000000);

    // when
    auto result = isRegFullyDefined(RAX,DOUBLE_WORD);

    // then
    EXPECT_EQ(result, true);
}

TEST(isRegFullyDefinedTests, undefinedButInIrrelevantArea8High){
    // given
    shadowRegisterState[RAX].reset();
    shadowRegisterState[RAX].set(0,true);
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0x0000000000000001);

    // when
    auto result = isRegFullyDefined(RAX,HIGHER_BYTE);

    // then
    EXPECT_EQ(result, true);
}
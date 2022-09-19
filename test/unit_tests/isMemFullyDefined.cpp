#include <iostream>
#include "gtest/gtest.h"
#include "../../src/runtimeLibrary/BinMsanApi.h"

TEST(isMemFullyDefinedTests, fullyDefined){
    // given
    auto *a = new uint64_t {12};

    // when
    auto result = isMemFullyDefined(a, 8);

    // then
    EXPECT_EQ(result, true);
}

TEST(isMemFullyDefinedTests, fullyUndefined){
    // given
    auto *a = new uint64_t;

    // when
    auto result = isMemFullyDefined(a, 8);

    // then
    EXPECT_EQ(result, false);
}
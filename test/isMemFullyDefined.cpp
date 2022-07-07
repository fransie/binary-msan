#include <cassert>
#include <iostream>
#include <msan.h>
#include "gtest/gtest.h"
#include "../runtimeLibrary/Interface.h"

TEST(isMemFullyDefinedTests, fullyDefined){
    // given
    auto *a = new uint64_t;
    *a = 12;

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
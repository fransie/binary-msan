#include <cassert>
#include <iostream>
#include <msan.h>
#include "gtest/gtest.h"
#include "../runtimeLibrary/Interface.h"

TEST(getRegisterShadowTests, width64){
    // given
    shadowRegisterState[0].set();
    EXPECT_EQ(shadowRegisterState[0].to_ullong(), UINT64_MAX);

    // when
    auto result = (uint64_t) getRegisterShadow(0, QUAD_WORD);

    // then
    EXPECT_EQ(result, UINT64_MAX);
}

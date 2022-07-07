#include <iostream>
#include <msan.h>
#include "gtest/gtest.h"
#include "../runtimeLibrary/Interface.h"

TEST(getRegisterShadowTests, width64){
    // given
    shadowRegisterState[0].set();
    EXPECT_EQ(shadowRegisterState[0].to_ullong(), UINT64_MAX);

    // when
    auto result = static_cast<uint64_t*>(getRegisterShadow(0, QUAD_WORD));

    // then
    EXPECT_EQ(*result, UINT64_MAX);
}

TEST(getRegisterShadowTests, width32){
    // given
    shadowRegisterState[0].set();
    EXPECT_EQ(shadowRegisterState[0].to_ullong(), UINT64_MAX);

    // when
    auto result = static_cast<uint32_t*>(getRegisterShadow(0, DOUBLE_WORD));

    // then
    EXPECT_EQ(*result, UINT32_MAX);
}

TEST(getRegisterShadowTests, width16){
    // given
    shadowRegisterState[0].set();
    EXPECT_EQ(shadowRegisterState[0].to_ullong(), UINT64_MAX);

    // when
    auto result = static_cast<uint16_t*>(getRegisterShadow(0, WORD));

    // then
    EXPECT_EQ(*result, UINT16_MAX);
}

TEST(getRegisterShadowTests, width8){
    // given
    shadowRegisterState[0].set();
    EXPECT_EQ(shadowRegisterState[0].to_ullong(), UINT64_MAX);

    // when
    auto result = static_cast<uint8_t*>(getRegisterShadow(0, BYTE));

    // then
    EXPECT_EQ(*result, UINT8_MAX);
}

TEST(getRegisterShadowTests, width8Highh){
    // given
    shadowRegisterState[0] = std::bitset<64>{0xffffffffffffff00};
    EXPECT_EQ(shadowRegisterState[0].to_ullong(), UINT64_MAX - 255);

    // when
    auto result = static_cast<uint8_t*>(getRegisterShadow(0, HIGHER_BYTE));

    // then
    EXPECT_EQ(*result, UINT8_MAX);
}

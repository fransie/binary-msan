#include <iostream>
#include <msan.h>
#include "gtest/gtest.h"
#include "../../runtimeLibrary/Interface.h"
#include "../../common/RegisterNumbering.h"

TEST(getRegisterShadowTests, width64){
    // given
    shadowRegisterState[RAX].set();
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), UINT64_MAX);

    // when
    auto result = static_cast<uint64_t*>(getRegisterShadow(RAX, QUAD_WORD));

    // then
    EXPECT_EQ(*result, UINT64_MAX);
}

TEST(getRegisterShadowTests, width32){
    // given
    shadowRegisterState[RAX].set();
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), UINT64_MAX);

    // when
    auto result = static_cast<uint32_t*>(getRegisterShadow(RAX, DOUBLE_WORD));

    // then
    EXPECT_EQ(*result, UINT32_MAX);
}

TEST(getRegisterShadowTests, width16){
    // given
    shadowRegisterState[RAX].set();
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), UINT64_MAX);

    // when
    auto result = static_cast<uint16_t*>(getRegisterShadow(RAX, WORD));

    // then
    EXPECT_EQ(*result, UINT16_MAX);
}

TEST(getRegisterShadowTests, width8){
    // given
    shadowRegisterState[RAX].set();
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), UINT64_MAX);

    // when
    auto result = static_cast<uint8_t*>(getRegisterShadow(RAX, BYTE));

    // then
    EXPECT_EQ(*result, UINT8_MAX);
}

TEST(getRegisterShadowTests, width8Highh){
    // given
    shadowRegisterState[RAX] = std::bitset<64>{0xffffffffffffff00};
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), UINT64_MAX - 255);

    // when
    auto result = static_cast<uint8_t*>(getRegisterShadow(RAX, HIGHER_BYTE));

    // then
    EXPECT_EQ(*result, UINT8_MAX);
}

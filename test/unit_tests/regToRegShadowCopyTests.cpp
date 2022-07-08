#include "gtest/gtest.h"
#include "../../runtimeLibrary/Interface.h"

TEST(regToRegShadowCopyTests, width64) {
    // given
    shadowRegisterState[0].set();
    shadowRegisterState[1] = std::bitset<64>{0xff00ff00ff00ff00};
    EXPECT_EQ(shadowRegisterState[0].to_ullong(), UINT64_MAX);
    EXPECT_EQ(shadowRegisterState[1].to_ullong(), 0xff00ff00ff00ff00);

    // when
    regToRegShadowCopy(0, QUAD_WORD, 1, QUAD_WORD);

    // then
    EXPECT_EQ(shadowRegisterState[0].to_ullong(), 0xff00ff00ff00ff00);
    EXPECT_EQ(shadowRegisterState[1].to_ullong(), 0xff00ff00ff00ff00);
}

TEST(regToRegShadowCopyTests, width32) {
    // given
    shadowRegisterState[0].set();
    shadowRegisterState[1] = std::bitset<64>{0xff00ff00ff00ff00};
    EXPECT_EQ(shadowRegisterState[0].to_ullong(), UINT64_MAX);
    EXPECT_EQ(shadowRegisterState[1].to_ullong(), 0xff00ff00ff00ff00);

    // when
    regToRegShadowCopy(0, DOUBLE_WORD, 1, DOUBLE_WORD);

    // then
    EXPECT_EQ(shadowRegisterState[0].to_ullong(), 0xffffffffff00ff00);
    EXPECT_EQ(shadowRegisterState[1].to_ullong(), 0xff00ff00ff00ff00);
}

TEST(regToRegShadowCopyTests, width16) {
    // given
    shadowRegisterState[0].set();
    shadowRegisterState[1] = std::bitset<64>{0xff00ff00ff00ff00};
    EXPECT_EQ(shadowRegisterState[0].to_ullong(), UINT64_MAX);
    EXPECT_EQ(shadowRegisterState[1].to_ullong(), 0xff00ff00ff00ff00);

    // when
    regToRegShadowCopy(0, WORD, 1, WORD);

    // then
    EXPECT_EQ(shadowRegisterState[0].to_ullong(), 0xffffffffffffff00);
    EXPECT_EQ(shadowRegisterState[1].to_ullong(), 0xff00ff00ff00ff00);
}

TEST(regToRegShadowCopyTests, width8) {
    // given
    shadowRegisterState[0].set();
    shadowRegisterState[1] = std::bitset<64>{0xff00ff00ff00ff01};
    EXPECT_EQ(shadowRegisterState[0].to_ullong(), UINT64_MAX);
    EXPECT_EQ(shadowRegisterState[1].to_ullong(), 0xff00ff00ff00ff01);

    // when
    regToRegShadowCopy(0, BYTE, 1, BYTE);

    // then
    EXPECT_EQ(shadowRegisterState[0].to_ullong(), 0xffffffffffffff01);
    EXPECT_EQ(shadowRegisterState[1].to_ullong(), 0xff00ff00ff00ff01);
}

TEST(regToRegShadowCopyTests, width8High) {
    // given
    shadowRegisterState[0].set();
    shadowRegisterState[1] = std::bitset<64>{0xff00ff00ff001a00};
    EXPECT_EQ(shadowRegisterState[0].to_ullong(), UINT64_MAX);
    EXPECT_EQ(shadowRegisterState[1].to_ullong(), 0xff00ff00ff001a00);

    // when
    regToRegShadowCopy(0, HIGHER_BYTE, 1, HIGHER_BYTE);

    // then
    EXPECT_EQ(shadowRegisterState[0].to_ullong(), 0xffffffffffff1aff);
    EXPECT_EQ(shadowRegisterState[1].to_ullong(), 0xff00ff00ff001a00);
}

TEST(regToRegShadowCopyTests, width8HighMixed1) {
    // given
    shadowRegisterState[0].set();
    shadowRegisterState[1] = std::bitset<64>{0x000000000000001a};
    EXPECT_EQ(shadowRegisterState[0].to_ullong(), UINT64_MAX);
    EXPECT_EQ(shadowRegisterState[1].to_ullong(), 0x000000000000001a);

    // when
    regToRegShadowCopy(0, HIGHER_BYTE, 1, BYTE);

    // then
    EXPECT_EQ(shadowRegisterState[0].to_ullong(), 0xffffffffffff1aff);
    EXPECT_EQ(shadowRegisterState[1].to_ullong(), 0x000000000000001a);
}

TEST(regToRegShadowCopyTests, width8HighMixed2) {
    // given
    shadowRegisterState[0].set();
    shadowRegisterState[1] = std::bitset<64>{0x0000000000001a00};
    EXPECT_EQ(shadowRegisterState[0].to_ullong(), UINT64_MAX);
    EXPECT_EQ(shadowRegisterState[1].to_ullong(), 0x0000000000001a00);

    // when
    regToRegShadowCopy(0, BYTE, 1, HIGHER_BYTE);

    // then
    EXPECT_EQ(shadowRegisterState[0].to_ullong(), 0xffffffffffffff1a);
    EXPECT_EQ(shadowRegisterState[1].to_ullong(), 0x0000000000001a00);
}
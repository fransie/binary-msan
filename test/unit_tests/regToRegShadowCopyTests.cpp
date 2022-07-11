#include "gtest/gtest.h"
#include "../../runtimeLibrary/Interface.h"
#include "../../common/RegisterNumbering.h"

TEST(regToRegShadowCopyTests, width64) {
    // given
    shadowRegisterState[RAX].set();
    shadowRegisterState[RCX] = std::bitset<64>{0xff00ff00ff00ff00};
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), UINT64_MAX);
    EXPECT_EQ(shadowRegisterState[RCX].to_ullong(), 0xff00ff00ff00ff00);

    // when
    regToRegShadowCopy(RAX, QUAD_WORD, RCX, QUAD_WORD);

    // then
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0xff00ff00ff00ff00);
    EXPECT_EQ(shadowRegisterState[RCX].to_ullong(), 0xff00ff00ff00ff00);
}

TEST(regToRegShadowCopyTests, width32) {
    // given
    shadowRegisterState[RAX].set();
    shadowRegisterState[RCX] = std::bitset<64>{0xff00ff00ff00ff00};
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), UINT64_MAX);
    EXPECT_EQ(shadowRegisterState[RCX].to_ullong(), 0xff00ff00ff00ff00);

    // when
    regToRegShadowCopy(RAX, DOUBLE_WORD, RCX, DOUBLE_WORD);

    // then
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0xffffffffff00ff00);
    EXPECT_EQ(shadowRegisterState[RCX].to_ullong(), 0xff00ff00ff00ff00);
}

TEST(regToRegShadowCopyTests, width16) {
    // given
    shadowRegisterState[RAX].set();
    shadowRegisterState[RCX] = std::bitset<64>{0xff00ff00ff00ff00};
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), UINT64_MAX);
    EXPECT_EQ(shadowRegisterState[RCX].to_ullong(), 0xff00ff00ff00ff00);

    // when
    regToRegShadowCopy(RAX, WORD, RCX, WORD);

    // then
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0xffffffffffffff00);
    EXPECT_EQ(shadowRegisterState[RCX].to_ullong(), 0xff00ff00ff00ff00);
}

TEST(regToRegShadowCopyTests, width8) {
    // given
    shadowRegisterState[RAX].set();
    shadowRegisterState[RCX] = std::bitset<64>{0xff00ff00ff00ff01};
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), UINT64_MAX);
    EXPECT_EQ(shadowRegisterState[RCX].to_ullong(), 0xff00ff00ff00ff01);

    // when
    regToRegShadowCopy(RAX, BYTE, RCX, BYTE);

    // then
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0xffffffffffffff01);
    EXPECT_EQ(shadowRegisterState[RCX].to_ullong(), 0xff00ff00ff00ff01);
}

TEST(regToRegShadowCopyTests, width8High) {
    // given
    shadowRegisterState[RAX].set();
    shadowRegisterState[RCX] = std::bitset<64>{0xff00ff00ff001a00};
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), UINT64_MAX);
    EXPECT_EQ(shadowRegisterState[RCX].to_ullong(), 0xff00ff00ff001a00);

    // when
    regToRegShadowCopy(RAX, HIGHER_BYTE, RCX, HIGHER_BYTE);

    // then
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0xffffffffffff1aff);
    EXPECT_EQ(shadowRegisterState[RCX].to_ullong(), 0xff00ff00ff001a00);
}

TEST(regToRegShadowCopyTests, width8HighMixed1) {
    // given
    shadowRegisterState[RAX].set();
    shadowRegisterState[RCX] = std::bitset<64>{0x000000000000001a};
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), UINT64_MAX);
    EXPECT_EQ(shadowRegisterState[RCX].to_ullong(), 0x000000000000001a);

    // when
    regToRegShadowCopy(RAX, HIGHER_BYTE, RCX, BYTE);

    // then
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0xffffffffffff1aff);
    EXPECT_EQ(shadowRegisterState[RCX].to_ullong(), 0x000000000000001a);
}

TEST(regToRegShadowCopyTests, width8HighMixed2) {
    // given
    shadowRegisterState[RAX].set();
    shadowRegisterState[RCX] = std::bitset<64>{0x0000000000001a00};
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), UINT64_MAX);
    EXPECT_EQ(shadowRegisterState[RCX].to_ullong(), 0x0000000000001a00);

    // when
    regToRegShadowCopy(RAX, BYTE, RCX, HIGHER_BYTE);

    // then
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0xffffffffffffff1a);
    EXPECT_EQ(shadowRegisterState[RCX].to_ullong(), 0x0000000000001a00);
}
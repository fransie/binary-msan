#include "gtest/gtest.h"
#include "../../src/runtimeLibrary/BinMsanApi.h"
#include "../../src/common/RegisterNumbering.h"
#include "../../src/common/Width.h"

TEST(propagateRegOrRegShadow, width64) {
    // given
    shadowRegisterState[RAX].reset();
    shadowRegisterState[RCX].set();
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0);

    // when
    propagateRegOrRegShadow(RAX, QUAD_WORD, RCX, QUAD_WORD);

    // then
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), UINT64_MAX);
}

TEST(propagateRegOrRegShadow, width32) {
    // given
    shadowRegisterState[RAX].reset();
    shadowRegisterState[RCX].set();
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0);

    // when
    propagateRegOrRegShadow(RAX, DOUBLE_WORD, RCX, DOUBLE_WORD);

    // then
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0x00000000ffffffff);
}

TEST(propagateRegOrRegShadow, width32Upper) {
    // given
    shadowRegisterState[RAX].set();
    shadowRegisterState[RCX].set();
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), UINT64_MAX);

    // when
    propagateRegOrRegShadow(RAX, DOUBLE_WORD, RCX, DOUBLE_WORD);

    // then
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0x00000000ffffffff);
}

TEST(propagateRegOrRegShadow, width16) {
    // given
    shadowRegisterState[RAX] = std::bitset<64>{0xff00000000000000};
    shadowRegisterState[RCX].set();
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0xff00000000000000);

    // when
    propagateRegOrRegShadow(RAX, WORD, RCX, WORD);

    // then
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0xff0000000000ffff);
}

TEST(propagateRegOrRegShadow, width8) {
    // given
    shadowRegisterState[RAX] = std::bitset<64>{0xff00000000000000};
    shadowRegisterState[RCX].set();
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0xff00000000000000);

    // when
    propagateRegOrRegShadow(RAX, BYTE, RCX, BYTE);

    // then
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0xff000000000000ff);
}

TEST(propagateRegOrRegShadow, width8Higher) {
    // given
    shadowRegisterState[RAX] = std::bitset<64>{0xff00000000000000};
    shadowRegisterState[RCX].set();
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0xff00000000000000);

    // when
    propagateRegOrRegShadow(RAX, HIGHER_BYTE, RCX, HIGHER_BYTE);

    // then
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0xff0000000000ff00);
}

TEST(propagateRegOrRegShadow, width8HigherMixed1) {
    // given
    shadowRegisterState[RAX] = std::bitset<64>{0xff00000000000000};
    shadowRegisterState[RCX].set();
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0xff00000000000000);

    // when
    propagateRegOrRegShadow(RAX, BYTE, RCX, HIGHER_BYTE);

    // then
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0xff000000000000ff);
}

TEST(propagateRegOrRegShadow, width8HigherMixed2) {
    // given
    shadowRegisterState[RAX] = std::bitset<64>{0xff00000000000000};
    shadowRegisterState[RCX].set();
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0xff00000000000000);

    // when
    propagateRegOrRegShadow(RAX, HIGHER_BYTE, RCX, BYTE);

    // then
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0xff0000000000ff00);
}


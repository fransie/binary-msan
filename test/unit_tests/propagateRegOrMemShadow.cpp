#include "gtest/gtest.h"
#include "../../src/runtimeLibrary/BinMsanApi.h"
#include "../../src/common/RegisterNumbering.h"
#include "../../src/common/Width.h"

TEST(propagateRegOrMemShadow, width64) {
    // given
    uint64_t *a = new uint64_t;
    shadowRegisterState[RAX].reset();
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0);

    // when
    propagateRegOrMemShadow(a, RAX, QUAD_WORD);

    // then
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), UINT64_MAX);
}

TEST(propagateRegOrMemShadow, width32) {
    // given
    uint32_t *a = new uint32_t;
    shadowRegisterState[RAX].reset();
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0);

    // when
    propagateRegOrMemShadow(a, RAX, DOUBLE_WORD);

    // then
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0x00000000ffffffff);
}

TEST(propagateRegOrMemShadow, width32Upper) {
    // given
    uint32_t *a = new uint32_t;
    shadowRegisterState[RAX].set();
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), UINT64_MAX);

    // when
    propagateRegOrMemShadow(a, RAX, DOUBLE_WORD);

    // then
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0x00000000ffffffff);
}

TEST(propagateRegOrMemShadow, width16) {
    // given
    uint16_t *a = new uint16_t;
    shadowRegisterState[RAX] = std::bitset<64>{0xff00000000000000};
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0xff00000000000000);

    // when
    propagateRegOrMemShadow(a, RAX, WORD);

    // then
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0xff0000000000ffff);
}

TEST(propagateRegOrMemShadow, width8) {
    // given
    uint8_t *a = new uint8_t;
    shadowRegisterState[RAX] = std::bitset<64>{0xff00000000000000};
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0xff00000000000000);

    // when
    propagateRegOrMemShadow(a, RAX, BYTE);

    // then
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0xff000000000000ff);
}

TEST(propagateRegOrMemShadow, width8Higher) {
    // given
    uint8_t *a = new uint8_t;
    shadowRegisterState[RAX] = std::bitset<64>{0xff00000000000000};
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0xff00000000000000);

    // when
    propagateRegOrMemShadow(a, RAX, HIGHER_BYTE);

    // then
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0xff0000000000ff00);
}

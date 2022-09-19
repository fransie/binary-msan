#include "gtest/gtest.h"
#include "../../src/runtimeLibrary/BinMsanApi.h"
#include "../../src/common/RegisterNumbering.h"
#include "../../src/common/Width.h"

TEST(memToRegShadowCopyTests, width64) {
    // given
    uint64_t *a = new uint64_t;
    shadowRegisterState[RAX].reset();
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0);

    // when
    memToRegShadowCopy((unsigned long) a, RAX, QUAD_WORD);

    // then
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), UINT64_MAX);
}

TEST(memToRegShadowCopyTests, width32) {
    // given
    uint32_t *a = new uint32_t;
    shadowRegisterState[RAX] = std::bitset<64>{0xffffffff00000000};
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0xffffffff00000000);

    // when
    memToRegShadowCopy((unsigned long) a, RAX, DOUBLE_WORD);

    // then
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0xffffffffffffffff);
}

TEST(memToRegShadowCopyTests, width16) {
    // given
    uint16_t *a = new uint16_t;
    shadowRegisterState[RAX].reset();
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0);

    // when
    memToRegShadowCopy((unsigned long) a, RAX, WORD);

    // then
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0x000000000000ffff);
}

TEST(memToRegShadowCopyTests, width8) {
    // given
    uint8_t *a = new uint8_t;
    shadowRegisterState[RAX].reset();
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0);

    // when
    memToRegShadowCopy((unsigned long) a, RAX, BYTE);

    // then
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0x00000000000000ff);
}

TEST(memToRegShadowCopyTests, width8High) {
    // given
    uint8_t *a = new uint8_t;
    shadowRegisterState[RAX].reset();
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0);

    // when
    memToRegShadowCopy((unsigned long) a, RAX, HIGHER_BYTE);

    // then
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0x000000000000ff00);
}
#include "gtest/gtest.h"
#include "../../runtimeLibrary/Interface.h"
#include "../../common/RegisterNumbering.h"
#include "../../common/Width.h"

TEST(memToRegShadowCopyTests, width64) {
    // given
    uint64_t *a = new uint64_t;
    shadowRegisterState[RAX].reset();
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0);

    // when
    memToRegShadowCopy(RAX, QUAD_WORD,(unsigned long) a);

    // then
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), UINT64_MAX);
}

TEST(memToRegShadowCopyTests, width32) {
    // given
    uint32_t *a = new uint32_t;
    shadowRegisterState[RAX] = std::bitset<64>{0xffffffff00000000};
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0xffffffff00000000);

    // when
    memToRegShadowCopy(RAX, DOUBLE_WORD,(unsigned long) a);

    // then
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0xffffffffffffffff);
}

TEST(memToRegShadowCopyTests, width16) {
    // given
    uint16_t *a = new uint16_t;
    shadowRegisterState[RAX].reset();
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0);

    // when
    memToRegShadowCopy(RAX, WORD,(unsigned long) a);

    // then
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0x000000000000ffff);
}

TEST(memToRegShadowCopyTests, width8) {
    // given
    uint8_t *a = new uint8_t;
    shadowRegisterState[RAX].reset();
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0);

    // when
    memToRegShadowCopy(RAX, BYTE,(unsigned long) a);

    // then
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0x00000000000000ff);
}

TEST(memToRegShadowCopyTests, width8High) {
    // given
    uint8_t *a = new uint8_t;
    shadowRegisterState[RAX].reset();
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0);

    // when
    memToRegShadowCopy(RAX, HIGHER_BYTE,(unsigned long) a);

    // then
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0x000000000000ff00);
}
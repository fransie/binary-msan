#include "gtest/gtest.h"
#include "../../runtimeLibrary/Interface.h"
#include "../../common/RegisterNumbering.h"

TEST(regToMemShadowCopyTests, width64) {
    // given
    uint64_t *a = new uint64_t;
    shadowRegisterState[RAX].reset();
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0);

    // when
    regToMemShadowCopy(RAX, QUAD_WORD,(unsigned long) a);

    // then
    EXPECT_EQ(isMemFullyDefined(a, 8), true);
}

TEST(regToMemShadowCopyTests, width32) {
    // given
    uint32_t *a = new uint32_t;
    shadowRegisterState[RAX].reset();
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0);

    // when
    regToMemShadowCopy(RAX, DOUBLE_WORD,(unsigned long) a);

    // then
    EXPECT_EQ(isMemFullyDefined(a, 4), true);
}

TEST(regToMemShadowCopyTests, width16) {
    // given
    uint16_t *a = new uint16_t;
    shadowRegisterState[RAX].reset();
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0);

    // when
    regToMemShadowCopy(RAX, WORD,(unsigned long) a);

    // then
    EXPECT_EQ(isMemFullyDefined(a, 2), true);
}

TEST(regToMemShadowCopyTests, width8) {
    // given
    uint8_t *a = new uint8_t;
    shadowRegisterState[RAX].reset();
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0);

    // when
    regToMemShadowCopy(RAX, BYTE,(unsigned long) a);

    // then
    EXPECT_EQ(isMemFullyDefined(a, 1), true);
}

TEST(regToMemShadowCopyTests, width8High) {
    // given
    uint8_t *a = new uint8_t;
    shadowRegisterState[RAX].reset();
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0);

    // when
    regToMemShadowCopy(RAX, HIGHER_BYTE,(unsigned long) a);

    // then
    EXPECT_EQ(isMemFullyDefined(a, 1), true);
}
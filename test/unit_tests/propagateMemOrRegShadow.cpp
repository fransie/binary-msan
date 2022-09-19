#include "gtest/gtest.h"
#include "../../src/runtimeLibrary/BinMsanApi.h"
#include "../../src/common/RegisterNumbering.h"
#include "../../src/common/Width.h"

TEST(propagateMemOrRegShadow, width64) {
    // given
    uint64_t *a = new uint64_t{12};
    auto shadow = reinterpret_cast<uint64_t*>(MEM_TO_SHADOW(a));
    EXPECT_EQ(*shadow, 0);
    shadowRegisterState[RAX].set();

    // when
    propagateMemOrRegShadow(a, RAX, QUAD_WORD);

    // then
    EXPECT_EQ(*shadow, UINT64_MAX);
}

TEST(propagateMemOrRegShadow, width32) {
    // given
    uint32_t *a = new uint32_t{12};
    auto shadow = reinterpret_cast<uint32_t*>(MEM_TO_SHADOW(a));
    EXPECT_EQ(*shadow, 0);
    shadowRegisterState[RAX] = std::bitset<64>{0x00000000ffffffff};

    // when
    propagateMemOrRegShadow(a, RAX, DOUBLE_WORD);

    // then
    EXPECT_EQ(*shadow, UINT32_MAX);
}

TEST(propagateMemOrRegShadow, width16) {
    // given
    uint16_t *a = new uint16_t{12};
    auto shadow = reinterpret_cast<uint16_t*>(MEM_TO_SHADOW(a));
    EXPECT_EQ(*shadow, 0);
    shadowRegisterState[RAX] = std::bitset<64>{0x000000000000ffff};

    // when
    propagateMemOrRegShadow(a, RAX, WORD);

    // then
    EXPECT_EQ(*shadow, UINT16_MAX);
}

TEST(propagateMemOrRegShadow, width8) {
    // given
    uint8_t *a = new uint8_t{12};
    auto shadow = reinterpret_cast<uint8_t*>(MEM_TO_SHADOW(a));
    EXPECT_EQ(*shadow, 0);
    shadowRegisterState[RAX] = std::bitset<64>{0x00000000000000ff};

    // when
    propagateMemOrRegShadow(a, RAX, BYTE);

    // then
    EXPECT_EQ(*shadow, UINT8_MAX);
}

TEST(propagateMemOrRegShadow, width8Higher) {
    // given
    uint8_t *a = new uint8_t{12};
    auto shadow = reinterpret_cast<uint8_t*>(MEM_TO_SHADOW(a));
    EXPECT_EQ(*shadow, 0);
    shadowRegisterState[RAX] = std::bitset<64>{0x000000000000ff00};

    // when
    propagateMemOrRegShadow(a, RAX, HIGHER_BYTE);

    // then
    EXPECT_EQ(*shadow, UINT8_MAX);
}
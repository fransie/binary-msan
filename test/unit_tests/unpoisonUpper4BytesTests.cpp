#include "gtest/gtest.h"
#include "../../runtimeLibrary/Interface.h"
#include "../../common/RegisterNumbering.h"

TEST(initUpper4BytesTests, init){
    // given
    shadowRegisterState[RAX].set();
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), UINT64_MAX);

    // when
    unpoisonUpper4Bytes(RAX);

    // then
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0x0000000ffffffff);
}

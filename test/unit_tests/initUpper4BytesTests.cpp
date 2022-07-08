#include "gtest/gtest.h"
#include "../../runtimeLibrary/Interface.h"

TEST(initUpper4BytesTests, init){
    // given
    shadowRegisterState[0].set();
    EXPECT_EQ(shadowRegisterState[0].to_ullong(), UINT64_MAX);

    // when
    initUpper4Bytes(0);

    // then
    EXPECT_EQ(shadowRegisterState[0].to_ullong(), 0x0000000ffffffff);
}

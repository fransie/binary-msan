#include "gtest/gtest.h"
#include "../../runtimeLibrary/Interface.h"


TEST(checkRegIsInitTests, fullyInit64) {
    // given
    shadowRegisterState[0].reset();
    EXPECT_EQ(shadowRegisterState[0].to_ullong(), 0);

    // when
    checkRegIsInit(0, QUAD_WORD);

    // then no error occurs
}

TEST(checkRegIsInitTests, fullyUninit64) {
    // given
    __msan_set_keep_going(1);
    shadowRegisterState[0].set();
    EXPECT_EQ(shadowRegisterState[0].to_ullong(), UINT64_MAX);

    // when/then
    __msan_set_expect_umr(1);
    checkRegIsInit(0, QUAD_WORD);

    // then
    __msan_set_expect_umr(0);
    __msan_set_keep_going(0);
}

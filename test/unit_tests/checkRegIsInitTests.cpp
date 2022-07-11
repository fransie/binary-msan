#include "gtest/gtest.h"
#include "../../runtimeLibrary/Interface.h"
#include "../../common/RegisterNumbering.h"
#include "../../common/Width.h"


TEST(checkRegIsInitTests, fullyInit64) {
    // given
    shadowRegisterState[RAX].reset();
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), 0);

    // when
    checkRegIsInit(RAX, QUAD_WORD);

    // then no error occurs
}

TEST(checkRegIsInitTests, fullyUninit64) {
    // given
    __msan_set_keep_going(1);
    shadowRegisterState[RAX].set();
    EXPECT_EQ(shadowRegisterState[RAX].to_ullong(), UINT64_MAX);

    // when/then
    __msan_set_expect_umr(1);
    checkRegIsInit(RAX, QUAD_WORD);

    // then
    __msan_set_expect_umr(0);
    __msan_set_keep_going(0);
}

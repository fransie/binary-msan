// COMPILE OPTIONS: -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/lib/msan -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/include/sanitizer/ -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/lib/  -L$BINMSAN_HOME/plugins_install -lbinmsan_lib


#include "../../src/runtimeLibrary/BinMsanApi.h"
#include "../../src/common/RegisterNumbering.h"
#include "../../src/common/Width.h"

int main() {
    // given
    setRegShadow(true,RAX,64);
    uint32_t *a = new uint32_t;
    checkRegIsInit(RAX,64);

    // when
    asm( "mov %0, %%eax" : : "m" (*a));

    // then this should be uninit
    checkRegIsInit(RAX,DOUBLE_WORD);
    return 0;
}

// EXPECTED: MemorySanitizer: use-of-uninitialized-value

// COMPILE OPTIONS: -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/lib/msan -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/include/sanitizer/ -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/lib/  -L$BINMSAN_HOME/plugins_install -linterface


#include <cstdint>
#include "../../runtimeLibrary/Interface.h"
#include "../../common/RegisterNumbering.h"
#include "../../common/Width.h"

int main(int argc, char** argv) {
    // given
    setRegShadow(true,RAX,64);
    uint8_t *a = new uint8_t;
    checkRegIsInit(RAX,64);


    // when
    asm( "mov %0, %%al" : : "m" (*a));

    // then this should be uninit
    checkRegIsInit(RAX,BYTE);
    return 0;
}

// EXPECTED: MemorySanitizer: use-of-uninitialized-value

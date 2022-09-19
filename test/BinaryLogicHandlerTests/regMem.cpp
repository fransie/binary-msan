// COMPILE OPTIONS: -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/lib/msan -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/include/sanitizer/ -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/lib/  -L$BINMSAN_HOME/plugins_install -lbinmsan_lib


#include <cassert>
#include <iostream>
#include "../../src/runtimeLibrary/BinMsanApi.h"
#include "../../src/common/RegisterNumbering.h"

int main() {
    // given
    shadowRegisterState[RAX] = std::bitset<64>{0x00a00000000000ff};
    uint64_t *a = new uint64_t{5};

    // when
    asm ("and %0, %%rax" : "=m" ( *a ));

    // then
    assert(shadowRegisterState[RAX].to_ullong() == 0x00a00000000000ff);
    std::cout << "Success." << std::endl;
    return 0;
}

// EXPECTED: Success.
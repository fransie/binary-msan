// COMPILE OPTIONS: -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/lib/msan -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/include/sanitizer/ -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/lib/  -L$BINMSAN_HOME/plugins_install -lbinmsan_lib
// HALT ON ERROR

#include <cassert>
#include <iostream>
#include "../../src/runtimeLibrary/BinMsanApi.h"
#include "../../src/common/RegisterNumbering.h"

int main() {
    // given
    shadowRegisterState[RBX] = std::bitset<64>{0x000f0000000000f0};

    // when
    asm ("jmp *%rbx");
}

// EXPECTED: MemorySanitizer: use-of-uninitialized-value
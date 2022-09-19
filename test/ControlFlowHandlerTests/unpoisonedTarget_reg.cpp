// COMPILE OPTIONS: -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/lib/msan -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/include/sanitizer/ -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/lib/  -L$BINMSAN_HOME/plugins_install -lbinmsan_lib
// HALT ON ERROR

#include <iostream>
#include "../../src/runtimeLibrary/BinMsanApi.h"
#include "../../src/common/RegisterNumbering.h"

int main() {
    // given
    shadowRegisterState[RBX] = std::bitset<64>{0x0};
    asm ("lea 2(%rip), %rbx");

    // when
    asm ("jmp *%rbx ;"
         "nop ;");

    // then no MSan warning should be issued -> execution would halt on MSan warning.
    std::cout << "Success." << std::endl;
}

// EXPECTED: Success.
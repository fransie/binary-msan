// COMPILE OPTIONS: -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/lib/msan -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/include/sanitizer/ -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/lib/  -L$BINMSAN_HOME/plugins_install -lbinmsan_lib
// HALT ON ERROR

#include <cassert>
#include <iostream>
#include "../../src/runtimeLibrary/BinMsanApi.h"
#include "../../src/common/RegisterNumbering.h"
#include "../../src/common/Width.h"

int main() {
    // given
    setRegShadow(true, RAX, QUAD_WORD);
    u_long *mem = new u_long;

    // when
    asm ("jmp *%0" : : "m" ( *mem ));
}

// EXPECTED: Uninitialized bytes
// COMPILE OPTIONS: -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/lib/msan -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/include/sanitizer/ -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/lib/  -L$BINMSAN_HOME/plugins_install -linterface
// HALT ON ERROR

#include <cassert>
#include <iostream>
#include "../../runtimeLibrary/Interface.h"
#include "../../common/RegisterNumbering.h"
#include "../../common/Width.h"

int main() {
    // given
    setRegShadow(true, RAX, QUAD_WORD);
    u_long *mem = new u_long;

    // when
    asm ("jmp *%0" : : "m" ( *mem ));
}

// EXPECTED: Uninitialized bytes
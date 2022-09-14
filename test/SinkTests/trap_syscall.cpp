// COMPILE OPTIONS: -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/lib/msan -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/include/sanitizer/ -I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/lib/  -L$BINMSAN_HOME/plugins_install -linterface


#include <unistd.h>
#include <iostream>
#include "../../runtimeLibrary/Interface.h"
#include "../../common/RegisterNumbering.h"

int main() {
    // define rax here because "new" is not instrumented yet and returns an uninit address in rax, which is wrong.
    setRegShadow(true,RAX,64);
    char *ptr = new char;
    write(1, ptr, 1);
    return 0;
}

// EXPECTED: MemorySanitizer: use-of-uninitialized-value
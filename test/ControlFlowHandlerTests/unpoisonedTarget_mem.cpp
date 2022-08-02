// COMPILE OPTIONS: -I/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/lib/msan -I/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/include/sanitizer/ -I/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/lib/  -L/home/franzi/Documents/binary-msan/plugins_install -linterface
// HALT ON ERROR

#include <iostream>
#include <cassert>
#include "../../runtimeLibrary/Interface.h"
#include "../../common/RegisterNumbering.h"
#include "../../common/Width.h"

int main() {
    // given
    setRegShadow(true, RAX, QUAD_WORD);
    u_int64_t *mem = new u_int64_t{1};
    asm ("lea 9(%%rip), %%r10 ;"
         "mov %%r10, %0 ;" :  "=m" (*mem) : : "r10" );

    // when
    asm ("jmp *%0 ;"
         "nop ;" : : "m" (*mem));

    // then no MSan warning should be issued -> execution would halt on MSan warning.
    std::cout << "Success." << std::endl;
}

// EXPECTED: Success.
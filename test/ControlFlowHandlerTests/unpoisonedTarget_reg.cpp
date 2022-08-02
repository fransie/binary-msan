// COMPILE OPTIONS: -I/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/lib/msan -I/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/include/sanitizer/ -I/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/lib/  -L/home/franzi/Documents/binary-msan/plugins_install -linterface
// HALT ON ERROR

#include <iostream>
#include "../../runtimeLibrary/Interface.h"
#include "../../common/RegisterNumbering.h"

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
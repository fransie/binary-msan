// BINMSAN COMPILE OPTIONS
// HALT ON ERROR

#include <iostream>
#include "../../src/runtimeLibrary/BinMsanApi.h"
#include "../../src/common/RegisterNumbering.h"

int main() {
    // given
    shadowRegisterState[R10] = std::bitset<64>{0x0};
    asm ("lea 3(%rip), %r10");

    // when
    asm ("jmp *%r10 ;"
         "nop ;");

    // then no MSan warning should be issued -> execution would halt on MSan warning.
    std::cout << "Success." << std::endl;
}

// EXPECTED: Success.
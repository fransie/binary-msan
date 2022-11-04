// BINMSAN COMPILE OPTIONS
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
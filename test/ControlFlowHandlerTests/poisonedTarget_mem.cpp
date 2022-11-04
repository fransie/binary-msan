// BINMSAN COMPILE OPTIONS
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
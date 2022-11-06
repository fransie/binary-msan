// BINMSAN COMPILE OPTIONS


#include <cassert>
#include <iostream>
#include "../../src/runtimeLibrary/BinMsanApi.h"
#include "../../src/common/RegisterNumbering.h"

int main() {
    // given
    shadowRegisterState[R10] = std::bitset<64>{0x00a00000000000ff};
    uint64_t *a = new uint64_t{5};

    // when
    asm ("and %0, %%r10" : "=m" ( *a ));

    // then
    assert(shadowRegisterState[R10].to_ullong() == 0x00a00000000000ff);
    std::cout << "Success." << std::endl;
    return 0;
}

// EXPECTED: Success.
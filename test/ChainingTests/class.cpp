// BINMSAN COMPILE OPTIONS

#include <iostream>
#include <vector>
#include "../../src/runtimeLibrary/BinMsanApi.h"
#include "../../src/common/RegisterNumbering.h"

class UumClass{
public:
    char *text = new char[10];
};

int main() {
    // define rax here because "new" is not instrumented yet and returns an uninit address in rax, which is wrong.
    setRegShadow(true,RAX,64);
    auto x = new UumClass;
    std::cout << x->text << std::endl;
    return 0;
}

// EXPECTED: MemorySanitizer: use-of-uninitialized-value
#include <iostream>
#include <vector>

class UumClass{
public:
    char *text = new char[10];
};

int main() {
    auto x = new UumClass;
    std::cout << x->text << std::endl;
    return 0;
}

// EXPECTED: MemorySanitizer: use-of-uninitialized-value
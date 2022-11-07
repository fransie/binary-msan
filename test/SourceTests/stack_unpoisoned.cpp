#include <iostream>
#include <cassert>

int main() {
    uint64_t ptr = 7;

    auto shadow = reinterpret_cast<uint64_t*>((unsigned long long)(ptr) ^ 0x500000000000ULL);
    assert(*shadow == 0);

    std::cout << "Success.";
    return 0;
}

// EXPECTED: Success.
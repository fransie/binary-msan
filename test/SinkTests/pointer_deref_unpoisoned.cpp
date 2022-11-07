// <empty>
// HALT ON ERROR

#include <iostream>

int main() {
    // given
    int number = 5;
    int *ptr = &number;
    int **double_ptr = &ptr;

    // when
    int n = **double_ptr;

    // then
    std::cout << "Success.";
    return 0;
}

// EXPECTED: Success.
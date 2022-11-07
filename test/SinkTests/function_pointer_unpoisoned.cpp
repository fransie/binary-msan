// <empty>
// HALT ON ERROR

#include <iostream>

int foo(){
    return 1;
}

int main() {
    int (*fcnptr)(){foo};
    fcnptr();
    std::cout << "Success." << std::endl;
    return 0;
}

// EXPECTED: Success.
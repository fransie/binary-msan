#include <iostream>

class someClass
{
public:
    int* ptr2Int;
};

int main(int argc, char** argv) {
    // create class so that pointer is stored on heap
    // uninit stack pointers are not supported yet
    someClass *obj = new someClass();
    int num = *obj->ptr2Int;
    std::cout << num;
    return 0;
}

// EXPECTED: MemorySanitizer: use-of-uninitialized-value
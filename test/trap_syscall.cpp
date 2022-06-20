#include <unistd.h>
#include <iostream>

int main ()
{
    char *ptr = new char;
    write(1, ptr, 1);
    return 0;
}

// EXPECTED: MemorySanitizer: use-of-uninitialized-value
#include <unistd.h>
#include <iostream>

int main ()
{
    int *a = new int[10];
    write(a[5], "xx\n", 2);
    return 0;
}

// EXPECTED: MemorySanitizer: use-of-uninitialized-value
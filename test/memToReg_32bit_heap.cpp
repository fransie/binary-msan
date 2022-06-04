#include <stdio.h>

int main(int argc, char** argv) {
    int *i = new int;
    if (*i){
        printf("xx\n");
    }
    return 0;
}

// EXPECTED: memToRegShadowCopy. Shadow of reg 0 is: 0xffffffff.

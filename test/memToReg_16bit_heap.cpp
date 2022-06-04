#include <stdio.h>

int main(int argc, char** argv) {
    short *i = new short;
    if (*i){
        printf("xx\n");
    }
    return 0;
}

// DISABLED: memToRegShadowCopy. Shadow of reg 0 is: 0xffff.

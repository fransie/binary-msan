#include <stdio.h>

int main(int argc, char** argv) {
    long long *i = new long long;
    if (*i){
        printf("xx\n");
    }
    return 0;
}

// EXPECTED: memToRegShadowCopy. Shadow of reg 0 is: 18446744073709551615

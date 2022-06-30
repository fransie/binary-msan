#include <iostream>

int calc(int a){
    if(a){
        return a;
    }
    return a * 2;
}

int main(int argc) {
    int a;
    __attribute__((musttail)) return calc(a);
}

// DISABLED
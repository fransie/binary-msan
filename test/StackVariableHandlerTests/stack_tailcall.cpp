// COMPILE-OPTIONS: -foptimize-tail-recursion

int calc(int a){
    return a * 2;
}

int main(int argc) {
    int a;
    if(a){
        return a;
    }
    return calc(a);
}

// EXPECTED: MemorySanitizer: use-of-uninitialized-value
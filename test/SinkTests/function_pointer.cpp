int main() {
    int (*fcnptr)();
    fcnptr();
    return 0;
}

// EXPECTED: MemorySanitizer: use-of-uninitialized-value
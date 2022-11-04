// COMPILE-OPTIONS: -ggdb

#include <iostream>

int main() {
    uint64_t a = 8;
    if (a == 8)
        return 0;
    return 2;
}

// This test cannot be verified as the other ones since a leaf function cannot call another function to print to stdout.
// Therefore, use the exit code to verify the correct behaviour.
// EXPECTED: Check manually for the exit code of this program with this command: `StackVariableHandlerTests/obj/stack_leaf_values_not_overwritten_sanitized && echo $?` - Last line should be 0.
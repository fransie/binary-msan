#include <sstream>
#include "Utils.h"

/**
 * Returns a string containing pushes to EFLAGS and all caller-saved general purpose registers, namely
 *  RAX, RCX, RDX, RSI, RDI, R8, R9, R10 , R11 as well as a decrement of the stack pointer to avoid
 *  overwriting values in the red zone.
 * @return string of assembly instructions
 */
std::string Utils::getStateSavingInstrumentation() {
    return std::string() +
           "lea rsp, [rsp - 100]\n" +
           "pushfq\n" +
           "push   rax\n" +
           "push   rcx\n" +
           "push   rdx\n" +
           "push   rsi\n" +
           "push   rdi\n" +
           "push   r8\n" +
           "push   r9\n" +
           "push   r10\n" +
           "push   r11\n";
}

/**
 * Returns a string containing pops into EFLAGS and all caller-saved general purpose registers, namely
 *  RAX, RCX, RDX, RSI, RDI, R8, R9, R10 , R11 as well as an increment to the stack pointer to avoid
 *  overwriting values in the red zone.
 * @return string of assembly instructions
 */
std::string Utils::getStateRestoringInstrumentation() {
    return std::string() +
           "pop   r11\n" +
           "pop   r10\n" +
           "pop   r9\n" +
           "pop   r8\n" +
           "pop   rdi\n" +
           "pop   rsi\n" +
           "pop   rdx\n" +
           "pop   rcx\n" +
           "pop   rax\n" +
           "popfq\n" +
           "lea rsp, [rsp + 100]\n";
}

unsigned int Utils::toHex(int num) {
    std::stringstream stream;
    stream << std::hex << num;
    return std::stoi(stream.str());
}
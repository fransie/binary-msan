//
// Created by Franziska Mäckel on 12.04.22.
//

#include "utils.h"

// TODO: save state sse and fpu registers + red zone
/**
 * Returns a string containing pushes to all caller-saved general purpose registers, namely
 *  RAX, RCX, RDX, RSI, RDI, R8, R9, R10 , R11.
 *  Number of instructions: 9.
 * @return string of assembly push instructions
 */
std::string utils::getPushCallerSavedRegistersInstrumentation(){
    return std::string() +
           "push   rax\n" +
           "push   rcx\n" +
           "push   rdx\n" +
           "push   rsi\n" +
           "push   rdi\n" +
           "push   r8w\n" +
           "push   r9w\n" +
           "push   r10w\n" +
           "push   r11w\n";
}

/**
 * Returns a string containing pops into all general purpose registers, namely
 *  RAX, RCX, RDX, RSI, RDI, R8, R9, R10 , R11 to restore caller-saved registers.
 *  Number of instructions: 9.
 * @return string of assembly pop instructions
 */
std::string utils::getPopCallerSavedRegistersInstrumentation(){
    return std::string() +
           "pop   r11w\n" +
           "pop   r10w\n" +
           "pop   r9w\n" +
           "pop   r8w\n" +
           "pop   rdi\n" +
           "pop   rsi\n" +
           "pop   rdx\n" +
           "pop   rcx\n" +
           "pop   rax\n";
}
//
// Created by Franziska Mäckel on 07.04.22.
//

#include "Interface.h"

// TODO: global variable is probably a bad idea
/**
 * This vector holds the current shadow state of the 16 general purpose registers. Upon initialisation,
 * each bit of all of them has the state "undefined" (1). Registers numbering: see file operand_csx86.cpp in zipr.
 */
std::vector<std::bitset<64>> shadowRegisterState = std::vector<std::bitset<64>>(16, std::bitset<64>{}.set());

/**
 * Represents the definedness of the EFLAGS register in one bit. Hence, this is only an approximation.
 */
bool eflagsDefined = true;

/**
 * Takes two ints representing general purpose registers and propagates the shadow value of the
 * source register to the destination register. Registers numbering: see file operand_csx86.cpp in zipr.
 *
 * @param dest the number of the destination register
 * @param source the number of the source register
 * @param width the width of the registers in bits. "0" denominates the second-least significant byte.
 */
void regToRegShadowCopy(const int dest, const int source, const int width){
    std::cout << "regToRegShadowCopy. Dest value: " << dest << ". Source value: " << source << ". Width: " << width;
    switch(width){
        case QUAD_WORD:
        case WORD:
        case BYTE:
            for (int position = 63; position >= (64 - width) ; position--){
                shadowRegisterState[dest].set(position, shadowRegisterState[source][position]);
            }
            break;
        case DOUBLE_WORD:
            for (int position = 63; position >= 32 ; position--) {
                shadowRegisterState[dest].set(position, shadowRegisterState[source][position]);
            }
            // Higher four bytes are zeroed for double word moves.
            for (int position = 31; position >= 0 ; position--) {
                    shadowRegisterState[dest].set(position, false);
            }
            break;
        case HIGHER_BYTE:
            for (int position = 63 - BYTE; position >= (64 - WORD) ; position--){
                shadowRegisterState[dest].set(position, shadowRegisterState[source][position]);
            }
            break;
        default:
            throw std::invalid_argument("Function regToRegShadowCopy was called with an unsupported width value.");
    }
    std::cout << ". New dest shadow: " << shadowRegisterState[dest].to_ullong() << std::endl;
}

//TODO: do the processing of width in instrumentation, not here
/**
 * Sets the state of the required number of bits of a register to defined. Registers numbering: see namespace Registers.
 * Use it to define the shadow state for an immediate mov. For example, if an immediate is moved into AL, only the lowest
 * 8 bits of RAX are set to defined. The only exception is 32-bit registers: Here, all 64 bits are set to defined
 * because the higher two bytes are zeroed out by 32-bit moves. Registers numbering: see file operand_csx86.cpp in zipr.
 *
 * @param reg the number of the register to be set to defined.
 * @param width the width of the register to be set to defined in bits. "0" denominates the second-least significant byte.
 */
void defineRegShadow(const int reg, int width){
    std::cout << "defineRegShadow. Register: " << reg << ". Width: " << width << std::endl;
    int startFrom = 0;
    if(width == HIGHER_BYTE){
        startFrom = 8;
    }
    if(width == DOUBLE_WORD){
        // Higher two bytes are zeroed for double word moves.
        width = 64;
    }
    for(int position = 63 - startFrom; position >= (64 - width) ; position--){
        shadowRegisterState[reg].set(position, 0);
    }
}

/**
 * Checks whether the first regWidth bits of the register referenced by <code>reg</code> are initialised. If not,
 * an MSan Warning is issued. Registers numbering: see file operand_csx86.cpp in zipr.
 * Special case: If regWidth is HIGHER_BYTE (e.g. AH), then the bits at position 8 - 15 are checked.
 * @param reg number of the register to be checked
 * @param regWidth width of the register in bits
 */
void checkRegIsInit(int reg, int regWidth) {
    std::cout << "checkRegIsInit. Register: " << reg << ". Width: " << regWidth << ". Register shadow: 0x" << std::hex << shadowRegisterState[reg].to_ullong() << std::endl;
    if(shadowRegisterState[reg].any()){
        int bit = 0;
        if(regWidth == HIGHER_BYTE){
            bit = 8;
            regWidth = 16;
        }
        for (; bit < regWidth; bit++){
            if(shadowRegisterState[reg].test(bit) == 1){
                __msan_warning();
                break;
            }
        }
    }
}

/**
 * Copies the shadow associated with <code>memAddress</code> into the shadow state of the register <code>reg</code>.
 * Instrument a 'mov reg, [memAddress]' with this so that the shadow is propagated correctly. Registers numbering:
 * see file operand_csx86.cpp in zipr.
 *
 * @param reg Number of the destination register.
 * @param regWidth Width of the destination register.
 * @param memAddress Source memory address.
 */
void memToRegShadowCopy(int reg, int regWidth, uptr memAddress){
    std::cout << "memToRegShadowCopy. Register: " << reg << ". RegWidth: " << regWidth << ". MemAddress: 0x" << std::hex << memAddress << "." << std::endl;
    if (!MEM_IS_APP(memAddress)) {
        std::cout << memAddress << " is not an application address." << std::endl;
        return;
    }
    // char pointers in C++ can read memory byte by byte
    auto memShadowAddress = reinterpret_cast<char*>(MEM_TO_SHADOW(memAddress));
    int position = 0;
    if(regWidth == HIGHER_BYTE){
        regWidth = 8;
        position = 8;
    }
    for (int byte = 0; byte < (regWidth / BYTE); byte++){
        char bits = *memShadowAddress;
        for (int x = 0; x < 8; x++){
            auto bit = (bits >> x) & 1U;
            shadowRegisterState[reg].set(position, bit);
            position++;
        }
        memShadowAddress++;
    }

    // double words are zero-extended to quad words upon mov -> clear higher 4 bytes
    if(regWidth == DOUBLE_WORD){
        for(int x = 32; x < 64; x++){
            shadowRegisterState[reg].set(x, false);
        }
    }
    std::cout << "memToRegShadowCopy. Shadow of reg " << reg << " is: 0x" << std::hex << shadowRegisterState[reg].to_ullong() << "." << std::endl;
}

/**
 * Sets the shadow of the EFLAGS registers according to a test instruction with one general purpose register included,
 * e.g. test eax, eax or test eax, 0. Registers numbering: see file operand_csx86.cpp in zipr.
 * @param reg number of the register.
 * @param width width of the register.
 */
void setFlagsAfterTest_Reg(int reg, int width) {
    if (shadowRegisterState[reg].none()){
        eflagsDefined = true;
    } else {
        int bit = 0;
        if(width == HIGHER_BYTE){
            bit = 8;
            width = 16;
        }
        for (; bit < width; bit++){
            if(shadowRegisterState[reg].test(bit) == 1){
                eflagsDefined = false;
                std::cout << "setFlagsAfterTest_Reg. Register: " << reg << ". RegWidth: " << width << ". Eflags init: " << std::boolalpha << eflagsDefined << std::endl;
                return;
            }
        }
        eflagsDefined =  true;
    }
    std::cout << "setFlagsAfterTest_Reg. Register: " << reg << ". RegWidth: " << width << ". Eflags init: " << std::boolalpha << eflagsDefined << std::endl;
}


/**
 * Sets the shadow of the EFLAGS registers according to a test instruction with two general purpose registers included,
 * e.g. test eax, ebx. Registers numbering: see file operand_csx86.cpp in zipr.
 * @param destReg number of the destination register.
 * @param srcReg number of the source register.
 * @param width width of the two registers used. In test operations, both registers are the same size.
 */
void setFlagsAfterTest_RegReg(int destReg, int srcReg, int width) {
    if(shadowRegisterState[destReg].none() && shadowRegisterState[srcReg].none()){
        eflagsDefined = true;
    } else {
        int bit = 0;
        if(width == HIGHER_BYTE){
            bit = 8;
            width = 16;
        }
        for (; bit < width; bit++){
            if(shadowRegisterState[destReg].test(bit) == 1){
                eflagsDefined = false;
                return;
            }
            if(shadowRegisterState[srcReg].test(bit) == 1){
                eflagsDefined = false;
                return;
            }
        }
        eflagsDefined =  true;
    }
    std::cout << "setFlagsAfterTest_RegReg. Dest: " << destReg << ". Source: " << srcReg << ". Width: " << width << ". Eflags init: " << std::boolalpha << eflagsDefined << std::endl;
}

/**
 * Verifies whether the EFLAGS register is initialised and if not, causes an msan warning.
 */
void checkEflags() {
    if(!eflagsDefined){
        __msan_warning();
    }
}

/**
 * Sets the state of RBP and RSP to initialised.
 */
void initGpRegisters() {
    std::cout << "Init rbp and rsp." << std::endl;
    shadowRegisterState[4].reset();
    shadowRegisterState[5].reset();
}

void regToMemShadowCopy(int reg, int regWidth, uptr memAddress) {
    std::cout << "regToMemShadowCopy. Register: " << reg << ". RegWidth: " << regWidth << ". MemAddress: 0x" << std::hex << memAddress << std::endl;
    int size = regWidth / BYTE;
    if(regWidth == HIGHER_BYTE){
        size = 1;
    }
    auto shadow = getRegisterShadow(reg, regWidth);
    __msan_partial_poison(reinterpret_cast<const void *>(memAddress), shadow, size);
}

void *getRegisterShadow(int reg, int regWidth) {
    auto shadowValue = shadowRegisterState[reg].to_ullong();
    switch (regWidth) {
        case QUAD_WORD:{
            auto *shadow_ptr = new uint64_t;
            *shadow_ptr = shadowValue;
            return reinterpret_cast<void *>(shadow_ptr);
        }
        case DOUBLE_WORD:{
            auto *shadow_ptr = new uint32_t;
            *shadow_ptr = static_cast<uint32_t>(shadowValue);
            return reinterpret_cast<void *>(shadow_ptr);
        }
        case WORD: {
            auto *shadow_ptr = new uint16_t;
            *shadow_ptr = static_cast<uint16_t>(shadowValue);
            return reinterpret_cast<void *>(shadow_ptr);
        }
        case HIGHER_BYTE:{
            auto *shadow_ptr = new uint8_t;
            shadowValue = shadowValue >> 8;
            *shadow_ptr = static_cast<uint8_t>(shadowValue);
            return reinterpret_cast<void *>(shadow_ptr);
        }
        case BYTE: {
            auto *shadow_ptr = new uint8_t;
            *shadow_ptr = static_cast<uint8_t>(shadowValue);
            return reinterpret_cast<void *>(shadow_ptr);
        }
        default:
            throw std::invalid_argument("Function regToRegShadowCopy was called with an unsupported width value.");
    }
}

/**
 * Defines <code>width</code> bytes of shadow memory corresponding to the memory starting from <code>memAddress</code>.
 * @param memAddress Address of the initialised memory.
 * @param width Width of the initialised memory in bytes.
 */
void defineMemShadow(uptr memAddress, int width) {
    std::cout << "defineMemShadow. MemAddress: 0x" << std::hex << memAddress << ". Width: " << width << std::endl;
    __msan_unpoison((void*)memAddress, width);
}

//
// Created by Franziska Mäckel on 07.04.22.
//

#include <iostream>
#include <msan.h>
#include "interface.h"
#include "msan_interface_internal.h"

// TODO: global variable is probably a bad idea
/**
 * This vector holds the current shadow state of the 16 general purpose registers. Upon initialisation,
 * each bit of all of them has the state "undefined" (1).
 */
std::vector<std::bitset<64>> shadowRegisterState = std::vector<std::bitset<64>>(16, std::bitset<64>{}.set());


/**
 * Takes two ints representing general purpose registers and propagates the shadow value of the
 * source register to the destination register. Registers numbering: see namespace Registers.
 *
 * @param dest the number of the destination register
 * @param source the number of the source register
 * @param width the width of the registers in bits. "0" denominates the second-least significant byte.
 */
void regToRegShadowCopy(const int dest, const int source, const int width){
    std::cout << "regToRegShadowCopy. Dest value: " << dest << ". Source value: " << source << ". Width: " << width << std::endl;
    auto destinationRegisterShadow = shadowRegisterState[dest];
    auto sourceRegisterShadow = shadowRegisterState[source];
    switch(width){
        default:
            std::cerr << "Function regToRegShadowCopy was called with an unsupported width value. Width: " << width << std::endl;
            throw std::invalid_argument("Function regToRegShadowCopy was called with an unsupported width value.");
        case QUAD_WORD:
            destinationRegisterShadow = sourceRegisterShadow;
            break;
        case DOUBLE_WORD:
            for (int position = 63; position < (position - width) ; position--){
                // Higher two bytes are zeroed for double word moves.
                if(position < 31){
                    destinationRegisterShadow.set(position, false);
                } else {
                    destinationRegisterShadow.set(position, sourceRegisterShadow[position]);
                }
            }
            break;
        case WORD:
        case BYTE:
            for (int position = 63; position < (position - width) ; position--){
                destinationRegisterShadow.set(position, sourceRegisterShadow[position]);
            }
            break;
        case HIGHER_BYTE:
            for (int position = 63 - 8; position < (position - width) ; position--){
                destinationRegisterShadow.set(position, sourceRegisterShadow[position]);
            }
            break;
    }
}


/**
 * Sets the state of the required number of bits of a register to defined. Registers numbering: see namespace Registers.
 * Use it to define the shadow state for an immediate mov. For example, if an immediate is moved into AL, only the lowest
 * 8 bits of RAX are set to defined. The only exception is 32-bit registers: Here, all 64 bits are set to defined
 * because the higher two bytes are zeroed out by 32-bit moves.
 *
 * @param reg the number of the register to be set to defined.
 * @param width the width of the register to be set to defined in bits. "0" denominates the second-least significant byte.
 */
void defineRegShadow(const int reg, int width){
    std::cout << "defineRegShadow. Register: " << reg << ". Width: " << width << std::endl;
    auto destinationRegisterShadow = shadowRegisterState[reg];
    int startFrom = 0;
    if(width == HIGHER_BYTE){
        startFrom = 8;
    }
    if(width == DOUBLE_WORD){
        // Higher two bytes are zeroed for double word moves.
        width = 64;
    }
    for(int position = 63 - startFrom; position < (position - width) ; position--){
        destinationRegisterShadow.set(position, false);
    }
}

/**
 * Checks whether the first regWidth bits of the register referenced by <code>reg</code> are initialised. If not,
 * an MSan Warning is issued.
 * Special case: If regWidth is HIGHER_BYTE (e.g. AH), then the bits at position 8 - 15 are checked.
 * @param reg number of the register to be checked
 * @param regWidth width of the register in bits
 */
void checkRegIsInit(int reg, int regWidth) {
    auto regShadow = shadowRegisterState[reg].to_ullong();
    std::cout << "checkRegIsInit. Register: " << reg << ". Width: " << regWidth << ". Register shadow as ulong: " <<  regShadow << std::endl;
    if(regShadow != 0){
        int bit = 0;
        if(regWidth == HIGHER_BYTE){
            bit = 8;
            regWidth = 16;
        }
        for (; bit < regWidth; bit++){
            if(shadowRegisterState[reg].test(bit) == 1){
                std::cout << "msan warning" << std::endl;
                break;
                //__msan_warning();
            }
        }
    }
}

/**
 * Copies the shadow associated with <code>memAddress</code> into the shadow state of the register <code>reg</code>.
 * Instrument a 'mov reg, [memAddress]' with this so that the shadow is propagated correctly.
 *
 * @param reg Number of the destination register.
 * @param regWidth Width of the destination register.
 * @param memAddress Source memory address.
 */
void memToRegShadowCopy(int reg, int regWidth, uptr memAddress){
    std::cout << "memToRegShadowCopy. Register: " << reg << ". RegWidth: " << regWidth << ". MemAddress: " << memAddress << std::endl;
    if (!MEM_IS_APP(memAddress)) {
        std::cout << memAddress << " is not an application address." << std::endl;
        return;
    }
    auto *memShadow = reinterpret_cast<std::int8_t *>(MEM_TO_SHADOW(memAddress));
    int position = 0;
    if(regWidth == HIGHER_BYTE){
        position = 8;
    }
    for (int byte = 0; byte < regWidth / BYTE; byte++){
        std::int8_t bits = *((memShadow) + byte * BYTE);
        std::cout << "byte: " << (unsigned short) bits << ". Bits: ";
        for (int x = 0; x < 8; x++){
            auto bit = (bits >> x) & 1U;
            std::cout << (unsigned short) bit << " " ;
            shadowRegisterState[reg].set(position, bit);
            position++;
        }
        std::cout << std::endl;
    }

    // double words are zero-extended to quad words upon mov -> clear higher 4 bytes
    if(regWidth == DOUBLE_WORD){
        for(int x = 32; x < 64; x++){
            shadowRegisterState[reg].set(x, false);
        }
    }
    std::cout << "memToRegShadowCopy. MemAddress: " << memAddress << ". Shadow of reg " << reg << " is: " << shadowRegisterState[reg].to_ullong() << std::endl;
}
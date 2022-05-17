//
// Created by Franziska Mäckel on 07.04.22.
//

#include <iostream>
#include "interface.h"

// TODO: global variable is probably a bad idea
/**
 * This vector holds the current shadow state of the 16 general purpose registers. Upon initialisation,
 * each bit of all of them has the state "undefined" (1).
 */
std::vector<std::bitset<64>> shadowRegisterState = std::vector<std::bitset<64>>(16, 1);

void checkMemComponentsInit(int baseReg, int baseRegWidth, int indexReg, int indexRegWidth);

/**
 * Takes two ints representing general purpose registers and propagates the shadow value of the
 * source register to the destination register. Registers numbering: see namespace Registers.
 *
 * @param dest the number of the destination register
 * @param source the number of the source register
 * @param width the width of the registers in bits. "0" denominates the second-least significant byte.
 */
void regToRegShadowCopy(const int dest, const int source, const int width){
    std::cout << "test  test " << std::endl;
    std::cout << "regToRegShadowCopy. Dest value: " << dest << ". Source value: " << source << ". Width: " << width << std::endl;
    auto destinationRegisterShadow = shadowRegisterState[dest];
    auto sourceRegisterShadow = shadowRegisterState[source];
    switch(width){
        default:
            std::cout << "ERROR: Wrong width." << std::endl;
            //throw std::invalid_argument("Function regToRegShadowCopy was called with an unsupported width value.");
            break;
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
 * Checks whether memOperand has an uninit component -> this would mean we throw an error, pointer dereference base + index * scale + displacement scale and displacement are always constants, we don't need to check them
 * @param baseReg
 * @param baseRegWidth
 * @param indexReg
 * @param indexRegWidth
 */
void checkMemComponentsInit(int baseReg, int baseRegWidth, int indexReg,
                            int indexRegWidth) {
    auto baseRegShadow = shadowRegisterState[baseReg].to_ullong();
    auto indexRegShadow = shadowRegisterState[indexReg].to_ullong();
    if(baseRegShadow != 0){
        int bit = 0;
        if(baseRegWidth == HIGHER_BYTE){
            bit = 8;
            baseRegWidth = 16;
        }
        for (; bit < baseRegWidth; bit++){
            if(bit == 1){
                std::cout << "msan no return" << std::endl;
            }
        }
    }
    if (indexRegShadow != 0){
        int bit = 0;
        if(indexRegWidth == HIGHER_BYTE){
            bit = 8;
            indexRegWidth = 16;
        }
        for (; bit < indexRegWidth; bit++){
            if(bit == 1){
                std::cout << "msan no return" << std::endl;
            }
        }
    }
}
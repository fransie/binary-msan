//
// Created by Franziska Mäckel on 07.04.22.
//

#include "interface.h"
#include <iostream>
#include <vector>
#include <climits>
#include <bitset>

// TODO: global variable is probably a bad idea
/**
 * This vector holds the current shadow state of the 16 general purpose registers. Upon initialisation,
 * all of them have the state "undefined".
 */
std::vector<std::bitset<64>> shadowRegisterState = std::vector<std::bitset<64>>(16, 0);

/**
 * Takes two ints representing general purpose registers and propagates the shadow value of the
 * source register to the destination register. Registers numbering: see namespace Registers.
 *
 * @param dest the number of the destination register
 * @param source the number of the source register
 */
 void regToRegShadowCopy(const int dest, const int source){
    std::cout << "Dest value: " << dest << ". Source value: " << source << std::endl;
    shadowRegisterState[dest] = shadowRegisterState[source];
}

/**
 * Sets the state of all bits of a register to defined. Registers numbering: see namespace Registers.
 *
 * @param reg the number of the register to be set to defined.
 */
void defineRegShadow(const int reg){
   shadowRegisterState[reg] = ULONG_MAX;
}




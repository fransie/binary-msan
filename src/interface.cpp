//
// Created by Franziska Mäckel on 07.04.22.
//

#include "interface.h"
#include <iostream>
#include <vector>

// TODO: global variable is probably a bad idea
std::vector<uint64_t> shadowRegisterState = std::vector<uint64_t>(16,0);


/**
 * Takes two ints representing general purpose registers and propagates the shadow value of the
 * source register to the destination register. Registers numbering: see namespace Registers.
 */
 void regToRegMove(const int dest, const int source){
    std::cout << "Dest value: " << dest << ". Source value: " << source << std::endl;
    shadowRegisterState[dest] = shadowRegisterState[source];
}




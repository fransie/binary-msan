//
// Created by Franziska Mäckel on 07.04.22.
//

#include "interface.h"
#include <iostream>
#include <vector>


void MSanInterface::testing(){
    std::cout << "hi";
}

/**
 * Takes two ints representing registers from Registers.cpp and propagates the shadow value of the
 * source register to the destination register.
 */
void MSanInterface::regToRegMove(const int dest, const int source){
    std::vector<std::string> testString {"hi", "du"};
    for (auto text : testString){
        std::cout << text << std::endl;
    }
    //shadowRegisters[dest] = shadowRegisters[source];
    //cout << "This is a test." << endl;
}

//
// Created by Franziska Mäckel on 05.06.22.
//

#ifndef BINARY_MSAN_INSTRUCTIONHANDLER_H
#define BINARY_MSAN_INSTRUCTIONHANDLER_H

#include <irdb-core>

class InstructionHandler {
public:
    virtual void instrument(IRDB_SDK::Instruction_t *instruction) = 0;
    virtual const std::vector<std::string> &getAssociatedInstructions() = 0;
};


#endif //BINARY_MSAN_INSTRUCTIONHANDLER_H

//
// Created by Franziska Mäckel on 05.06.22.
//

#ifndef BINARY_MSAN_HANDLER_H
#define BINARY_MSAN_HANDLER_H

#include <irdb-core>

class Handler {
public:
    virtual void instrument(IRDB_SDK::Instruction_t *instruction) = 0;
    virtual const std::string &getAssociatedInstruction() = 0;
};


#endif //BINARY_MSAN_HANDLER_H

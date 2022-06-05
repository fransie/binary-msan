//
// Created by Franziska Mäckel on 05.06.22.
//

#ifndef BINARY_MSAN_TESTHANDLER_H
#define BINARY_MSAN_TESTHANDLER_H


#include "Handler.h"

class TestHandler : public Handler{
public:
    explicit TestHandler(IRDB_SDK::FileIR_t *fileIr);

    void instrument(IRDB_SDK::Instruction_t *instruction) override;
    const std::string &getAssociatedInstruction() override;

private:
    std::string associatedInstruction;
    IRDB_SDK::FileIR_t *fileIr;
};


#endif //BINARY_MSAN_TESTHANDLER_H

//
// Created by Franziska Mäckel on 01.07.22.
//

#ifndef BINARY_MSAN_COMPAREHANDLER_H
#define BINARY_MSAN_COMPAREHANDLER_H


#include "InstructionHandler.h"

class CompareHandler : public InstructionHandler {
public:
    explicit CompareHandler(IRDB_SDK::FileIR_t *fileIr);
    void instrument(IRDB_SDK::Instruction_t *instruction) override;

    const std::vector<std::string> &getAssociatedInstructions() override;
private:
    std::vector<std::string> associatedInstructions {"cmp"};
    IRDB_SDK::FileIR_t *fileIr;

};


#endif //BINARY_MSAN_COMPAREHANDLER_H

//
// Created by Franziska Mäckel on 07.06.22.
//

#ifndef BINARY_MSAN_JUMPHANDLER_H
#define BINARY_MSAN_JUMPHANDLER_H

#include "irdb-transform"
#include "Handler.h"
#include "RuntimeLib.h"
#include "Utils.h"

class JumpHandler : public Handler {
public:
    explicit JumpHandler(IRDB_SDK::FileIR_t *fileIr);
    ~JumpHandler() = default;

    void instrument(IRDB_SDK::Instruction_t *instruction) override;
    const std::vector<std::string> &getAssociatedInstructions() override;

private:
    std::vector<std::string> associatedInstructions {"jz", "je"};
    IRDB_SDK::FileIR_t *fileIr;

};


#endif //BINARY_MSAN_JUMPHANDLER_H

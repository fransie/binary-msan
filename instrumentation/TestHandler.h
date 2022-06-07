//
// Created by Franziska Mäckel on 05.06.22.
//

#ifndef BINARY_MSAN_TESTHANDLER_H
#define BINARY_MSAN_TESTHANDLER_H

#include <irdb-transform>
#include "Handler.h"
#include "CapstoneService.h"
#include "RuntimeLib.h"
#include "Utils.h"

class TestHandler : public Handler{
public:
    explicit TestHandler(IRDB_SDK::FileIR_t *fileIr);
    ~TestHandler() = default;

    const std::vector<std::string> &getAssociatedInstructions() override;
    void instrument(IRDB_SDK::Instruction_t *instruction) override;

private:
    std::vector<std::string> associatedInstructions {"test"};
    std::unique_ptr<CapstoneService> capstone;
    IRDB_SDK::FileIR_t *fileIr;

    void instrumentSingleRegTest(IRDB_SDK::Instruction_t *instruction);
    void instrumentRegRegTest(IRDB_SDK::Instruction_t *instruction);
};


#endif //BINARY_MSAN_TESTHANDLER_H

#ifndef BINARY_MSAN_MOVHANDLER_H
#define BINARY_MSAN_MOVHANDLER_H

#include <irdb-core>
#include "DisassemblyService.h"
#include "InstructionHandler.h"

class MovHandler : public InstructionHandler {
public:
    explicit MovHandler(IRDB_SDK::FileIR_t *fileIr);

    void instrument(IRDB_SDK::Instruction_t *instruction) override;
    const std::vector<std::string> &getAssociatedInstructions() override;

private:
    std::vector<std::string> associatedInstructions {"mov"};
    std::unique_ptr<DisassemblyService> capstone;
    IRDB_SDK::FileIR_t *fileIr;

    void instrumentImmToRegMove(IRDB_SDK::Instruction_t *instruction);
    void instrumentImmToMemMove(IRDB_SDK::Instruction_t *instruction);
    void instrumentMemToRegMove(IRDB_SDK::Instruction_t *instruction);
    void instrumentRegToMemMove(IRDB_SDK::Instruction_t *instruction);
    void instrumentRegToRegMove(IRDB_SDK::Instruction_t *instruction);
};


#endif //BINARY_MSAN_MOVHANDLER_H

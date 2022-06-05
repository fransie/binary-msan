//
// Created by Franziska Mäckel on 04.06.22.
//

#ifndef BINARY_MSAN_MOVHANDLER_H
#define BINARY_MSAN_MOVHANDLER_H

#include <irdb-core>
#include <irdb-transform>
#include "CapstoneService.h"
#include "RuntimeLib.h"
#include "Handler.h"
#include "Utils.h"
#include "MemoryAccessHandler.h"

class MovHandler : public Handler {
public:
    explicit MovHandler(IRDB_SDK::FileIR_t *fileIr);

    void instrument(IRDB_SDK::Instruction_t *instruction) override;
    std::string &getAssociatedInstruction() override;


private:
    std::string associatedInstruction = "mov";
    std::unique_ptr<CapstoneService> capstone;
    IRDB_SDK::FileIR_t *fileIr;

    void instrumentImmToRegMove(IRDB_SDK::Instruction_t *instruction);
    void instrumentRegToRegMove(IRDB_SDK::Instruction_t *instruction);
    void instrumentMemToRegMove(IRDB_SDK::Instruction_t *instruction);
    std::string getMemoryOperandDisassembly(IRDB_SDK::Instruction_t *instruction);

};


#endif //BINARY_MSAN_MOVHANDLER_H

#ifndef BINARY_MSAN_JUMPHANDLER_H
#define BINARY_MSAN_JUMPHANDLER_H

#include "irdb-transform"
#include "InstructionHandler.h"
#include "DisassemblyService.h"

class JumpHandler : public InstructionHandler {
public:
    explicit JumpHandler(IRDB_SDK::FileIR_t *fileIr);
    ~JumpHandler() = default;

    IRDB_SDK::Instruction_t* instrument(IRDB_SDK::Instruction_t *instruction) override;
    bool isResponsibleFor(IRDB_SDK::Instruction_t *instruction) override;

private:
    std::vector<std::string> associatedInstructions {"ja", "jae", "jb", "jbe", "jc", "jcxz", "je", "jecxz", "jg", "jge",
                                                     "jl", "jle", "jna", "jnae", "jnb", "jnbe", "jnc", "jne", "jng",
                                                     "jnge", "jnl", "jnle", "jno", "jnp", "jns", "jnz", "jo", "jp",
                                                     "jpe", "jpo", "jrcxz", "js", "jz"};
    std::vector<std::string> cxInstructions {"jcxz", "jecxz", "jrcxz"};

    std::unique_ptr<DisassemblyService> capstone;
    IRDB_SDK::FileIR_t *fileIr;

    IRDB_SDK::Instruction_t* checkEflags(IRDB_SDK::Instruction_t *instruction);
    IRDB_SDK::Instruction_t* checkCx(std::unique_ptr<IRDB_SDK::DecodedInstruction_t> &decodedInstr, IRDB_SDK::Instruction_t *instruction);
};


#endif //BINARY_MSAN_JUMPHANDLER_H

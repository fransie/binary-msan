
#ifndef BINARY_MSAN_JUMPHANDLER_H
#define BINARY_MSAN_JUMPHANDLER_H

#include "irdb-transform"
#include "InstructionHandler.h"
#include "RuntimeLib.h"
#include "Utils.h"
#include "CapstoneService.h"

class JumpHandler : public InstructionHandler {
public:
    explicit JumpHandler(IRDB_SDK::FileIR_t *fileIr);
    ~JumpHandler() = default;

    void instrument(IRDB_SDK::Instruction_t *instruction) override;
    const std::vector<std::string> &getAssociatedInstructions() override;

private:
    std::vector<std::string> associatedInstructions {"ja", "jae", "jb", "jbe", "jc", "jcxz", "je", "jecxz", "jg", "jge",
                                                     "jl", "jle", "jna", "jnae", "jnb", "jnbe", "jnc", "jne", "jng",
                                                     "jnge", "jnl", "jnle", "jno", "jnp", "jns", "jnz", "jo", "jp",
                                                     "jpe", "jpo", "jrcxz", "js", "jz"};
    std::vector<std::string> cxInstructions {"jcxz", "jecxz", "jrcxz"};

    std::unique_ptr<CapstoneService> capstone;
    IRDB_SDK::FileIR_t *fileIr;

    void checkEflags(IRDB_SDK::Instruction_t *instruction);
    void checkCx(std::unique_ptr<IRDB_SDK::DecodedInstruction_t> &decodedInstr, IRDB_SDK::Instruction_t *instruction);
};


#endif //BINARY_MSAN_JUMPHANDLER_H

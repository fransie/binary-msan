#ifndef BINARY_MSAN_CONTROLFLOWHANDLER_H
#define BINARY_MSAN_CONTROLFLOWHANDLER_H

#include "irdb-transform"
#include "InstructionHandler.h"
#include "DisassemblyService.h"

/**
 * Handles the branching instructions call, jump and conditional jumps. It checks whether the jump/call target
 * is initialised and for conditional jumps it is additionally verified that the register related to the condition
 * (either EFLAGS or RCX) is initialised.
 */
class ControlFlowHandler : public InstructionHandler {
public:
    explicit ControlFlowHandler(IRDB_SDK::FileIR_t *fileIr) : InstructionHandler(fileIr) {
        associatedInstructions = {"call", "jmp", "ja", "jae", "jb", "jbe", "jc", "jcxz", "je", "jecxz", "jg", "jge",
                                  "jl", "jle", "jna", "jnae", "jnb", "jnbe", "jnc", "jne", "jng",
                                  "jnge", "jnl", "jnle", "jno", "jnp", "jns", "jnz", "jo", "jp",
                                  "jpe", "jpo", "jrcxz", "js", "jz"};
    };

    IRDB_SDK::Instruction_t *instrument(IRDB_SDK::Instruction_t *instruction) override;

private:
    std::vector<std::string> cxJumps{"jcxz", "jecxz", "jrcxz"};
    std::vector<std::string> eflagsJumps{"ja", "jae", "jb", "jbe", "jc", "je", "jg", "jge",
                                         "jl", "jle", "jna", "jnae", "jnb", "jnbe", "jnc", "jne", "jng",
                                         "jnge", "jnl", "jnle", "jno", "jnp", "jns", "jnz", "jo", "jp",
                                         "jpe", "jpo", "js", "jz"};

    IRDB_SDK::Instruction_t *
    checkCx(std::unique_ptr<IRDB_SDK::DecodedInstruction_t> &decodedInstr, IRDB_SDK::Instruction_t *instruction);

    IRDB_SDK::Instruction_t *checkEflags(IRDB_SDK::Instruction_t *instruction);
    IRDB_SDK::Instruction_t *checkReg(IRDB_SDK::Instruction_t *instruction, std::unique_ptr<IRDB_SDK::DecodedInstruction_t> &decodedInstr);
    IRDB_SDK::Instruction_t *checkMem(IRDB_SDK::Instruction_t *instruction, std::unique_ptr<IRDB_SDK::DecodedInstruction_t> &decodedInstr);
};


#endif //BINARY_MSAN_CONTROLFLOWHANDLER_H

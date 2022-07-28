#ifndef BINARY_MSAN_DISASSEMBLYSERVICE_H
#define BINARY_MSAN_DISASSEMBLYSERVICE_H

#include <capstone.h>
#include <irdb-core>

/**
 * Offers access to miscellaneous disassembling functionality.
 */
class DisassemblyService {
public:
    DisassemblyService();
    ~DisassemblyService();

    x86_reg getRegister(IRDB_SDK::Instruction_t *instruction, int operandNumber);
    static bool isHigherByteRegister(x86_reg capstoneRegNumber);
    unsigned int getRegWidth(IRDB_SDK::Instruction_t *instruction, int operandNum);
    int getBaseRegWidth(IRDB_SDK::Instruction_t *instruction);
    int getIndexRegWidth(IRDB_SDK::Instruction_t *instruction);
    static std::string getMemoryOperandDisassembly(IRDB_SDK::Instruction_t *instruction);
    static std::vector<size_t> getCallInstructionPosition(const std::vector<IRDB_SDK::Instruction_t *> &instructions);
    int getRegWidthInMemOperand(IRDB_SDK::Instruction_t *instruction);

private:
    csh capstoneHandle{};
    cs_insn* getCapstoneInstruction(IRDB_SDK::Instruction_t *instruction);
    static int convertX86RegNumberToWidth(x86_reg regNumber);
    static int getPositionOfMemOperand(cs_insn *capstoneInstruction);

};

#endif //BINARY_MSAN_DISASSEMBLYSERVICE_H

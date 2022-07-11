#include "CapstoneService.h"
#include "Utils.h"
#include "../common/Width.h"

CapstoneService::CapstoneService() {
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &capstoneHandle) != CS_ERR_OK){
        throw std::runtime_error("Error opening capstone handle. Abort.");
    }
    cs_option(capstoneHandle, CS_OPT_DETAIL, CS_OPT_ON);
}

CapstoneService::~CapstoneService() {
    cs_close(&capstoneHandle);
}

x86_reg CapstoneService::getRegister(IRDB_SDK::Instruction_t *instruction, int operandNumber) {
    cs_insn* capstoneInstruction = getCapstoneInstruction(instruction);
    auto x86Register = capstoneInstruction->detail->x86.operands[operandNumber].reg;
    cs_free(capstoneInstruction, 1);
    return x86Register;
}

bool CapstoneService::isHigherByteRegister(x86_reg capstoneRegNumber) {
    switch(capstoneRegNumber){
        case X86_REG_AH:
        case X86_REG_CH:
        case X86_REG_BH:
        case X86_REG_DH:
            return true;
        default:
            return false;
    }
}

/**
 * Returns the width of the register operand denoted by <code>operandNum</code>. For example, operandNum = 1 returns
 * the width of the second operand of <code>instruction</code>. The operand has to be a general purpose register.
 * @param instruction The instruction from which we want to get the operand width.
 * @param operandNum The operand number.
 * @return Hexadecimal width of the operand/register in bits.
 */
unsigned int CapstoneService::getRegWidth(IRDB_SDK::Instruction_t *instruction, int operandNum) {
    auto operands = IRDB_SDK::DecodedInstruction_t::factory(instruction)->getOperands();
    auto width = operands[operandNum]->getArgumentSizeInBits();

    auto regNumber = getRegister(instruction, operandNum);
    if(isHigherByteRegister(regNumber)){
        width = HIGHER_BYTE;
    }
    return Utils::toHex(width);
}

/**
 * Gets the width if the base register used in the memory operand of this instruction in bits.
 * Special case: For registers AH, CH, BH, DH the value HIGHER_BYTE (0) is returned.
 *
 * This function assumes that there is only memory operand in any given assembly instruction.
 *
 * @param instruction instruction in which to find the width of the base register used in the memory operand
 * @return width of base register in bits
 */
int CapstoneService::getBaseRegWidth(IRDB_SDK::Instruction_t *instruction) {
    cs_insn* capstoneInstruction = getCapstoneInstruction(instruction);
    int numberOfMemOperand = getPositionOfMemOperand(capstoneInstruction);

    auto mem = capstoneInstruction->detail->x86.operands[numberOfMemOperand].mem;
    auto width = convertX86RegNumberToWidth(mem.base);
    cs_free(capstoneInstruction, 1);
    return Utils::toHex(width);
}

/**
 * Gets the width if the index register used in the memory operand of this instruction in bits.
 * Special case: For registers AH, CH, BH, DH the value HIGHER_BYTE (0) is returned.
 *
 * This function assumes that there is only memory operand in any given assembly instruction.
 *
 * @param instruction instruction in which to find the width of the index register used in the memory operand
 * @return width of index register in bits
 */
int CapstoneService::getIndexRegWidth(IRDB_SDK::Instruction_t *instruction) {
    cs_insn* capstoneInstruction = getCapstoneInstruction(instruction);
    int numberOfMemOperand = getPositionOfMemOperand(capstoneInstruction);
    auto mem = capstoneInstruction->detail->x86.operands[numberOfMemOperand].mem;
    auto width = convertX86RegNumberToWidth(mem.index);
    cs_free(capstoneInstruction, 1);
    return Utils::toHex(width);
}

/**
 * Converts an IRDB_SKD::Instruction to a Capstone instruction. After finishing the work with this returned pointer,
 * make sure so call `cs_free(<capstoneInstruction>, 1);` to free its memory.
 * @param instruction IRDB instruction to be transformed
 * @return cs_insn* pointer to a capstone instruction
 */
cs_insn* CapstoneService::getCapstoneInstruction(IRDB_SDK::Instruction_t *instruction){
    const auto dataBits = instruction->getDataBits();
    uint8_t* rawBytes = new uint8_t[dataBits.length()];
    for (unsigned long x = 0; x < dataBits.length(); x++){
        rawBytes[x] = dataBits[x];
    }
    cs_insn *capstoneInstruction;
    size_t count = cs_disasm(capstoneHandle, rawBytes, dataBits.length(), 0x1000, 0, &capstoneInstruction);
    if (count == 0){
        throw std::runtime_error("Failed to disassemble instruction " + instruction->getDisassembly());
    }
    return capstoneInstruction;
}

/**
 * Takes an x86_reg enum value and returns the register's width in bits. Special case: For registers AH, CH, BH, DH the value
 * HIGHER_BYTE (0) is returned.
 * @param regNumber x86_reg enum value
 * @return register width in bits
 */
int CapstoneService::convertX86RegNumberToWidth(x86_reg regNumber) {
    switch(regNumber){
        case X86_REG_AL:
        case X86_REG_CL:
        case X86_REG_BL:
        case X86_REG_DL:
        case X86_REG_SPL:
        case X86_REG_BPL:
        case X86_REG_SIL:
        case X86_REG_DIL:
        case X86_REG_R8B:
        case X86_REG_R9B:
        case X86_REG_R10B:
        case X86_REG_R11B:
        case X86_REG_R12B:
        case X86_REG_R13B:
        case X86_REG_R14B:
        case X86_REG_R15B:
            return BYTE;

        case X86_REG_AH:
        case X86_REG_CH:
        case X86_REG_BH:
        case X86_REG_DH:
            return HIGHER_BYTE;

        case X86_REG_AX:
        case X86_REG_CX:
        case X86_REG_BX:
        case X86_REG_DX:
        case X86_REG_SP:
        case X86_REG_BP:
        case X86_REG_SI:
        case X86_REG_DI:
        case X86_REG_R8W:
        case X86_REG_R9W:
        case X86_REG_R10W:
        case X86_REG_R11W:
        case X86_REG_R12W:
        case X86_REG_R13W:
        case X86_REG_R14W:
        case X86_REG_R15W:
            return WORD;

       case X86_REG_EAX:
       case X86_REG_ECX:
       case X86_REG_EDX:
       case X86_REG_EBX:
       case X86_REG_ESP:
       case X86_REG_EBP:
       case X86_REG_ESI:
       case X86_REG_EDI:
       case X86_REG_R8D:
       case X86_REG_R9D:
       case X86_REG_R10D:
       case X86_REG_R11D:
       case X86_REG_R12D:
       case X86_REG_R13D:
       case X86_REG_R14D:
       case X86_REG_R15D:
            return DOUBLE_WORD;

       case X86_REG_RAX:
       case X86_REG_RCX:
       case X86_REG_RDX:
       case X86_REG_RBX:
       case X86_REG_RSP:
       case X86_REG_RBP:
       case X86_REG_RSI:
       case X86_REG_RDI:
       case X86_REG_R8:
       case X86_REG_R9:
       case X86_REG_R10:
       case X86_REG_R11:
       case X86_REG_R12:
       case X86_REG_R13:
       case X86_REG_R14:
       case X86_REG_R15:
            return QUAD_WORD;

        default:
            //TODO: improve error handling
            std::cerr << "Register was not general purpose, abort." << std::endl;
    }
}

/**
 * Returns the position of the memory operand of an instruction, assuming there can only be one memory operand.
 * @param capstoneInstruction instruction to find the mem operand in
 * @return position of the memory operand in the instruction
 */
int CapstoneService::getPositionOfMemOperand(cs_insn *capstoneInstruction){
    for (int i = 0; i <= capstoneInstruction->detail->x86.operands->size; i++){
        if(capstoneInstruction->detail->x86.operands[i].type == X86_OP_MEM){
            return i;
        }
    }
    std::cerr << "No memory operand was found in operands " << capstoneInstruction->op_str << std::endl;
}

std::string CapstoneService::getMemoryOperandDisassembly(IRDB_SDK::Instruction_t *instruction) {
    auto disassembly = instruction->getDisassembly();
    auto openBracketPosition = disassembly.find_first_of('[');
    if(openBracketPosition == std::string::npos){
        std::cerr << "movHandler: Instruction " << instruction->getDisassembly() << " does not include a memory operand. Abort." << std::endl;
        throw std::invalid_argument("movHandler: Instruction " + instruction->getDisassembly() + " does not include a memory operand. Abort.");
    }
    auto closingBracketPosition = disassembly.find_first_of(']');
    auto len = closingBracketPosition - openBracketPosition;
    auto substring = disassembly.substr(openBracketPosition, len + 1);
    return substring;
}

std::vector<size_t> CapstoneService::getCallInstructionPosition(const std::vector<IRDB_SDK::Instruction_t *> &instructions) {
    std::vector<size_t> result {};
    for (size_t x = 0; x < instructions.size(); x++){
        auto decodedInstruction = IRDB_SDK::DecodedInstruction_t::factory(instructions[x]);
        if(decodedInstruction->getMnemonic() == "call"){
            result.push_back(x);
        }
    }
    return result;
}

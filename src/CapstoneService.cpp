//
// Created by Franziska Mäckel on 12.04.22.
//

#include "CapstoneService.h"
#include "interface.h"

CapstoneService::CapstoneService() {
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &capstoneHandle) != CS_ERR_OK){
        //TODO: error handling
    }
    cs_option(capstoneHandle, CS_OPT_DETAIL, CS_OPT_ON);
}

CapstoneService::~CapstoneService() {
    cs_close(&capstoneHandle);
}

x86_reg CapstoneService::getRegister(IRDB_SDK::Instruction_t *instruction, int operandNumber) {
    const auto dataBits = instruction->getDataBits();
    const auto opcode = reinterpret_cast<const uint8_t*>(dataBits.c_str());
    cs_insn *capstoneInstruction;
    size_t count = cs_disasm(capstoneHandle, opcode, sizeof(opcode)-1, 0x1000, 0, &capstoneInstruction);
    if (count == 0){
        //TODO: error handling of cs_disasm
        std::cout << "ERROR in getRegister";
    }
    auto x86Register = capstoneInstruction->detail->x86.operands[operandNumber].reg;
    cs_free(capstoneInstruction, count);
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

int CapstoneService::getOperandWidth(IRDB_SDK::Instruction_t *instruction) {
    auto operands = IRDB_SDK::DecodedInstruction_t::factory(instruction)->getOperands();
    auto width = operands[0]->getArgumentSizeInBits();

    auto regNumber = getRegister(instruction, 0);
    if(isHigherByteRegister(regNumber)){
        width = HIGHER_BYTE;
    }

    // Value is interpreted as hex in binary (due to zipr? idk), therefore convert to hex value.
    std::stringstream width_decimal;
    width_decimal << std::hex << width;
    return std::stoi(width_decimal.str());
}

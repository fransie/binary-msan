#include <irdb-elfdep>
#include "LeaHandler.h"
#include "RuntimeLib.h"
#include "Utils.h"
#include "../common/Width.h"

using namespace IRDB_SDK;
using namespace std;

IRDB_SDK::Instruction_t *LeaHandler::instrument(IRDB_SDK::Instruction_t *instruction) {
    auto decodedInstruction = DecodedInstruction_t::factory(instruction);
    auto memOperand = decodedInstruction->getOperands()[1];

    std::cout << "LeaHandler::instrument. Instruction: " << decodedInstruction->getDisassembly() << std::endl;
    if(memOperand->hasBaseRegister() && memOperand->hasIndexRegister()){
        return instrumentRegRegLea(instruction);
    } else if (memOperand->hasBaseRegister() != memOperand->hasIndexRegister()){
        return instrumentRegLea(instruction);
    } else if(!memOperand->hasBaseRegister() && !memOperand->hasIndexRegister()) {
        return instrumentImmLea(instruction);
    }
    return instruction;
}

IRDB_SDK::Instruction_t *LeaHandler::instrumentImmLea(IRDB_SDK::Instruction_t *instruction) {
    auto reg = DecodedInstruction_t::factory(instruction)->getOperand(0)->getRegNumber();
    auto width = disassemblyService->getRegWidth(instruction, 0);
    // Double-word results clear the higher 4 bytes of a general purpose register.
    if(width == DOUBLE_WORD){
        width = QUAD_WORD;
    }
    string instrumentation = Utils::getStateSavingInstrumentation() +
        "mov dil, 1\n" +      // isInited
        "mov rsi, %%1\n" +    // reg
        "mov rdx, %%2\n" +    // regWidth
        "call 0\n" +
        Utils::getStateRestoringInstrumentation();
    vector<basic_string<char>> instrumentationParams {to_string(reg), to_string(width)};
    const auto new_instr = IRDB_SDK::insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation, instrumentationParams);
    auto calls = DisassemblyService::getCallInstructionPosition(new_instr);
    new_instr[calls[0]]->setTarget(RuntimeLib::setRegShadow);
    return new_instr.back();
}


IRDB_SDK::Instruction_t *LeaHandler::instrumentRegRegLea(IRDB_SDK::Instruction_t *instruction) {
    auto decodedInstruction = DecodedInstruction_t::factory(instruction);
    auto destReg = decodedInstruction->getOperands()[0]->getRegNumber();
    auto destWidth = decodedInstruction->getOperands()[0]->getArgumentSizeInBits();
    auto memOperand = decodedInstruction->getOperands()[1];
    auto baseReg = memOperand->getBaseRegister();
    auto indexReg = memOperand->getIndexRegister();
    auto width = disassemblyService->getRegWidthInMemOperand(instruction);

    string instrumentation = string() +
                             Utils::getStateSavingInstrumentation() +
                             "mov rdi, %%1\n" +     // reg1
                             "mov rsi, %%2\n" +     // reg1Width
                             "mov rdx, %%3\n" +     // reg2
                             "mov rcx, %%2\n" +     // reg2Width
                             "call 0\n"       +     // isRegOrRegFullyDefined
                             "mov dil, al\n" +      // isInited
                             "mov rsi, %%4\n" +     // reg
                             "mov rdx, %%5\n" +     // regWidth
                             "call 0\n";            // setRegShadow
    if(destWidth == DOUBLE_WORD){
        instrumentation = instrumentation +
                            "mov rdi, %%4\n" +    // reg
                            "call 0\n";           // unpoisonUpper4Bytes
    }
    instrumentation = instrumentation + Utils::getStateRestoringInstrumentation();
    vector<basic_string<char>> instrumentationParams {to_string(baseReg),
                                                      to_string(Utils::toHex(width)),
                                                      to_string(indexReg),
                                                      to_string(destReg),
                                                      to_string(Utils::toHex(destWidth))};
    const auto new_instr = ::IRDB_SDK::insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation, instrumentationParams);
    auto calls = DisassemblyService::getCallInstructionPosition(new_instr);
    new_instr[calls[0]]->setTarget(RuntimeLib::isRegOrRegFullyDefined);
    new_instr[calls[1]]->setTarget(RuntimeLib::setRegShadow);
    if(destWidth == DOUBLE_WORD) {
        new_instr[calls[2]]->setTarget(RuntimeLib::unpoisonUpper4Bytes);
    }
    return new_instr.back();
}

IRDB_SDK::Instruction_t *LeaHandler::instrumentRegLea(IRDB_SDK::Instruction_t *instruction) {
    auto decodedInstruction = DecodedInstruction_t::factory(instruction);
    auto destReg = decodedInstruction->getOperands()[0]->getRegNumber();
    auto destWidth = decodedInstruction->getOperands()[0]->getArgumentSizeInBits();
    auto memOperand = decodedInstruction->getOperands()[1];
    u_int32_t regInMemOperand;
    if(memOperand->hasBaseRegister()){
        regInMemOperand = memOperand->getBaseRegister();
    } else if(memOperand->hasIndexRegister()){
        regInMemOperand = memOperand->getIndexRegister();
    } else {
        throw invalid_argument("LeaHandler::instrumentRegLea: Memory operand of " + instruction->getDisassembly() + "doesn't have a register.");
    }
    auto width = disassemblyService->getRegWidthInMemOperand(instruction);

    string instrumentation = string() +
                             Utils::getStateSavingInstrumentation() +
                             "mov rdi, %%1\n" +     // reg
                             "mov rsi, %%2\n" +     // regWidth
                             "call 0\n"       +     // isRegFullyDefined
                             "mov dil, al\n" +      // isInited
                             "mov rsi, %%3\n" +     // reg
                             "mov rdx, %%4\n" +     // regWidth
                             "call 0\n";            // setRegShadow
    if(destWidth == DOUBLE_WORD){
        instrumentation = instrumentation +
                          "mov rdi, %%3\n" +        // reg
                          "call 0\n";               // unpoisonUpper4Bytes
    }
    instrumentation = instrumentation + Utils::getStateRestoringInstrumentation();
    vector<basic_string<char>> instrumentationParams {to_string(regInMemOperand),
                                                      to_string(Utils::toHex(width)),
                                                      to_string(destReg),
                                                      to_string(Utils::toHex(destWidth))};
    const auto new_instr = ::IRDB_SDK::insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation, instrumentationParams);
    auto calls = DisassemblyService::getCallInstructionPosition(new_instr);
    new_instr[calls[0]]->setTarget(RuntimeLib::isRegFullyDefined);
    new_instr[calls[1]]->setTarget(RuntimeLib::setRegShadow);
    if(destWidth == DOUBLE_WORD) {
        new_instr[calls[2]]->setTarget(RuntimeLib::unpoisonUpper4Bytes);
    }
    return new_instr.back();
}

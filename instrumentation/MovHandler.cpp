//
// Created by Franziska Mäckel on 04.06.22.
//

#include "MovHandler.h"
#include "CapstoneService.h"

using namespace IRDB_SDK;
using namespace std;


// Achtung: there is also mov to control or debug segments -> handle every case (GPR, immediate, memory, ect.)
// here explicitly, not with plain "else". Control and debug segments can be recognised with operand->isSpecialRegister().
// TODO: Are moves with moffs (e.g. opcode A3) also handled as memory operands?
// TODO: segment registers?
/**
 * Takes a mov instruction and inserts instrumentation before it so that the shadow is handled correctly.
 */
void MovHandler::instrument(Instruction_t *instruction){
    auto decodedInstruction = DecodedInstruction_t::factory(instruction);
    vector<shared_ptr<DecodedOperand_t>> operands = decodedInstruction->getOperands();
    if(operands[0]->isGeneralPurposeRegister()){
        if(operands[1]->isGeneralPurposeRegister()){
            // reg to reg
            instrumentRegToRegMove(instruction);
        } else if (operands[1]->isConstant()){
            // immediate to reg
            instrumentImmToRegMove(instruction);
        } else if (operands[1]->isMemory()) {
            // mem to reg
            instrumentMemToRegMove(instruction);
        } else if (operands[1]->isSegmentRegister()){
            // Sreg to reg
        }
    } else if (operands[0]->isMemory()) {
        if(operands[1]->isGeneralPurposeRegister()){
            // reg to mem
            instrumentRegToMemMove(instruction);
        } else if (operands[1]->isSegmentRegister()){
            // Sreg to mem
        } else if (operands[1]->isConstant()){
            // immediate to mem
            instrumentImmToMemMove(instruction);
        }
    } else if (operands[0]->isSegmentRegister()){
        if(operands[1]->isGeneralPurposeRegister()){
            // reg to Sreg
        } else if (operands[1]->isMemory()){
            // sreg to mem
        }
    }
}

void MovHandler::instrumentImmToRegMove(Instruction_t *instruction) {
    auto operands = DecodedInstruction_t::factory(instruction)->getOperands();
    auto dest = operands[0]->getRegNumber();
    cout << "Instruction: " << instruction->getDisassembly() << " at " << instruction->getAddress()->getVirtualOffset() << ". Destination register: " << (int) dest << " and immediate: " << operands[1]->getConstant() << endl;


    auto width = capstone->getRegWidth(instruction, 0);
    string instrumentation = string() +
                             Utils::getPushCallerSavedRegistersInstrumentation() +
                             "mov dil, 0\n" +    // initState
                             "mov rsi, %%1\n" +    // reg
                             "mov rdx, %%2\n" +    // regWidth
                             "call 0\n" +
                             Utils::getPopCallerSavedRegistersInstrumentation();
    vector<basic_string<char>> instrumentationParams {to_string((int)dest), to_string(width)};
    const auto new_instr = IRDB_SDK::insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation, instrumentationParams);
    auto calls = CapstoneService::getCallInstructionPosition(new_instr);
	new_instr[calls[0]]->setTarget(RuntimeLib::setRegShadow);
}

/**
 * Takes a move instruction from one general purpose registers to another and inserts shadow propagating
 * instrumentation before the instruction.
 * @param instruction a pointer to the move instruction
 */
void MovHandler::instrumentRegToRegMove(Instruction_t *instruction) {
    const auto operands = DecodedInstruction_t::factory(instruction)->getOperands();
    const auto dest = operands[0]->getRegNumber();
    const auto source = operands[1]->getRegNumber();
    cout << "Instruction: " << instruction->getDisassembly() << " at " << instruction->getAddress()->getVirtualOffset() << ". Destination register: " << dest << " and source: " << source << endl;

    auto destWidth = capstone->getRegWidth(instruction, 0);
    auto srcWidth = capstone->getRegWidth(instruction, 1);
    // Higher four bytes are zeroed for double word moves.
    if(destWidth == Utils::toHex(DOUBLE_WORD)){
        string instrumentation = string() +
                                Utils::getPushCallerSavedRegistersInstrumentation() +
                                "mov rdi, %%1\n" +    // dest
                                "mov rsi, %%2\n" +    // destWidth
                                "mov rdx, %%3\n"      // src
                                "mov rcx, %%4\n"      // srcWidth
                                "call 0\n" +
                                "mov rdi, %%1\n" +    // reg
                                "call 0\n" +
                                Utils::getPopCallerSavedRegistersInstrumentation();
        vector<basic_string<char>> instrumentationParams {to_string(dest), to_string(destWidth), to_string(source),
                                                          to_string(srcWidth)};
        const auto new_instr = ::IRDB_SDK::insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation, instrumentationParams);
        auto calls = CapstoneService::getCallInstructionPosition(new_instr);
        new_instr[calls[0]]->setTarget(RuntimeLib::regToRegShadowCopy);
        new_instr[calls[1]]->setTarget(RuntimeLib::initUpper4Bytes);
    } else {
        string instrumentation = string() +
                                 Utils::getPushCallerSavedRegistersInstrumentation() +
                                 "mov rdi, %%1\n" +    // dest
                                 "mov rsi, %%2\n" +    // destWidth
                                 "mov rdx, %%3\n"      // src
                                 "mov rcx, %%4\n"      // srcWidth
                                 "call 0\n" +
                                 Utils::getPopCallerSavedRegistersInstrumentation();
        vector<basic_string<char>> instrumentationParams {to_string(dest), to_string(destWidth), to_string(source),
                                                          to_string(srcWidth)};
        const auto new_instr = ::IRDB_SDK::insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation, instrumentationParams);
        auto calls = CapstoneService::getCallInstructionPosition(new_instr);
        new_instr[calls[0]]->setTarget(RuntimeLib::regToRegShadowCopy);
    }
}

void MovHandler::instrumentMemToRegMove(Instruction_t *instruction) {
    auto operands = DecodedInstruction_t::factory(instruction)->getOperands();
    auto dest = operands[0]->getRegNumber();
    cout << "instrumentMemToRegMove. Instruction: " << instruction->getDisassembly() << " at " << instruction->getAddress()->getVirtualOffset() << ". Destination register: " << (int) dest << " and mem: " << operands[1]->getString() << endl;

    instruction = MemoryAccessInstrumentation::instrumentMemRef(operands[1], instruction, capstone, fileIr);
    auto memoryDisassembly = capstone->getMemoryOperandDisassembly(instruction);
    auto width = capstone->getRegWidth(instruction, 0);
    // Higher four bytes are zeroed for double word moves.
    if(width == Utils::toHex(DOUBLE_WORD)){
        string instrumentation = string() +
                                 Utils::getPushCallerSavedRegistersInstrumentation() +
                                 "mov rdi, %%1\n" +    // reg
                                 "mov rsi, %%2\n" +    // regWidth
                                 "lea rdx, %%3\n" +    // memAddr
                                 "call 0\n" +
                                 "mov rdi, %%1\n" +    // reg
                                 "call 0\n" +
                                 Utils::getPopCallerSavedRegistersInstrumentation();
        vector<basic_string<char>> instrumentationParams {to_string(dest), to_string(width), memoryDisassembly};
        const auto new_instr = ::IRDB_SDK::insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation, instrumentationParams);
        auto calls = CapstoneService::getCallInstructionPosition(new_instr);
        new_instr[calls[0]]->setTarget(RuntimeLib::memToRegShadowCopy);
        new_instr[calls[1]]->setTarget(RuntimeLib::initUpper4Bytes);
    } else {
        string instrumentation = string() +
                                 Utils::getPushCallerSavedRegistersInstrumentation() +
                                 "mov rdi, %%1\n" +    // reg
                                 "mov rsi, %%2\n" +    // regWidth
                                 "lea rdx, %%3\n" +    // memAddr
                                 "call 0\n" +
                                 Utils::getPopCallerSavedRegistersInstrumentation();
        vector<basic_string<char>> instrumentationParams {to_string(dest), to_string(width), memoryDisassembly};
        const auto new_instr = ::IRDB_SDK::insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation, instrumentationParams);
        auto calls = CapstoneService::getCallInstructionPosition(new_instr);
        new_instr[calls[0]]->setTarget(RuntimeLib::memToRegShadowCopy);
    }
}

void MovHandler::instrumentRegToMemMove(IRDB_SDK::Instruction_t *instruction) {
    // instrument mem operation
    cout << "instrumentRegToMemMove. Instruction: " << instruction->getDisassembly() << " at " << instruction->getAddress()->getVirtualOffset() << endl;
    auto operands = DecodedInstruction_t::factory(instruction)->getOperands();
    instruction = MemoryAccessInstrumentation::instrumentMemRef(operands[0], instruction, capstone, fileIr);

    auto src = operands[1]->getRegNumber();
    auto width = capstone->getRegWidth(instruction, 1);
    auto memoryDisassembly = capstone->getMemoryOperandDisassembly(instruction);
    string instrumentation = string() +
                             Utils::getPushCallerSavedRegistersInstrumentation() +
                             "mov rdi, %%1\n" +    // reg
                             "mov rsi, %%2\n" +    // regWidth
                             "lea rdx, %%3\n" +    // memAddr
                             "call 0\n" +
                             Utils::getPopCallerSavedRegistersInstrumentation();
    vector<basic_string<char>> instrumentationParams {to_string(src), to_string(width), memoryDisassembly};
    const auto new_instr = ::IRDB_SDK::insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation, instrumentationParams);
    auto calls = CapstoneService::getCallInstructionPosition(new_instr);
	new_instr[calls[0]]->setTarget(RuntimeLib::regToMemShadowCopy);
}

void MovHandler::instrumentImmToMemMove(IRDB_SDK::Instruction_t *instruction) {
    cout << "instrumentImmToMemMove: " << instruction->getDisassembly() << " at " << instruction->getAddress()->getVirtualOffset() << endl;
    auto operands = DecodedInstruction_t::factory(instruction)->getOperands();
    auto dest = capstone->getMemoryOperandDisassembly(instruction);
    auto destWidth = operands[0]->getArgumentSizeInBytes();
    string instrumentation = string() +
                             Utils::getPushCallerSavedRegistersInstrumentation() +
                             "lea rdi, %%1\n" +    // first argument
                             "mov rsi, %%2\n" +    // second argument
                             "call 0\n" +
                             Utils::getPopCallerSavedRegistersInstrumentation();
    vector<basic_string<char>> instrumentationParams {dest, to_string(Utils::toHex(destWidth))};
    const auto new_instr = IRDB_SDK::insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation, instrumentationParams);
    auto calls = CapstoneService::getCallInstructionPosition(new_instr);
	new_instr[calls[0]]->setTarget(RuntimeLib::__msan_unpoison);
}

MovHandler::MovHandler(FileIR_t *fileIr) : fileIr(fileIr){
    capstone = make_unique<CapstoneService>();
}

const vector<std::string> & MovHandler::getAssociatedInstructions() {
    return associatedInstructions;
}


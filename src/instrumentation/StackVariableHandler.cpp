#include <irdb-transform>
#include "../common/RegisterNumbering.h"
#include "DisassemblyService.h"
#include "RuntimeLib.h"
#include "StackVariableHandler.h"
#include "Utils.h"

using namespace std;

size_t RED_ZONE_SIZE = 128;

StackVariableHandler::StackVariableHandler(IRDB_SDK::FileIR_t *fileIr) : fileIr(fileIr) {}

/**
 * Inserts instrumentation after the <code>mov rbp, rsp</code> instruction in the function prologue to poison
 * the stack frame and/or red zone in case there are local variables in this function.
 *
 * The function depends on a "regular" function prologue similar to this:
 * push rbp
 * mov rbp, rsp
 * [sub rsp, x]
 *
 * Achtung: Currently, only the 256 bytes below the stack pointer UPON FUNCTION ENTRY are poisoned for leaf functions.
 * However, the red zones moves along with the stack pointer if it is changed. Hence, false negatives might occur
 * if there are pushes/pops or other instruction affecting the stack pointer in a leaf function. This function
 * poisons double the size of the red zone (128 byte) as a "buffer" but this might not always be enough.
 *
 * @param functionAnalysis analysis of the function to be instrumented.
 */
void StackVariableHandler::instrument(unique_ptr<FunctionAnalysis> &functionAnalysis) {
    std::cout << "StackVariableHandler: Function " << functionAnalysis->getFunction()->getName() << std::endl;
    auto function = functionAnalysis->getFunction();
    // getStackFrameSize() looks for the first occurrence of a `sub rsp|esp, x` instruction and returns x
    auto stackFrameSize = function->getStackFrameSize();
    bool hasStackPointerSub = (stackFrameSize != 0);
    bool canUseRedZone = functionAnalysis->isLeafFunction;

    if (!canUseRedZone && !hasStackPointerSub) {
        // do nothing
        return;
    }

    string instrumentation = Utils::getStateSavingInstrumentation();
    vector<basic_string<char>> instrumentationParams = vector<basic_string<char>>{"", ""};

    if (hasStackPointerSub) {
        poisonStackframe(instrumentation);
        instrumentationParams[0] = Utils::toHex(stackFrameSize);
    }
    if (canUseRedZone) {
        poisonRedZone(instrumentation);
        instrumentationParams[1] = Utils::toHex(RED_ZONE_SIZE);
    }
    instrumentation += Utils::getStateRestoringInstrumentation();

    IRDB_SDK::Instruction_t* instructionToBeInstrumented;
    vector<IRDB_SDK::Instruction_t *> new_instr;
    if(hasStackPointerSub){
        instructionToBeInstrumented = getSpSub(function);
        new_instr = IRDB_SDK::insertAssemblyInstructionsAfter(fileIr, instructionToBeInstrumented, instrumentation,
                                                              instrumentationParams);
    } else if (function->getUseFramePointer()){
        instructionToBeInstrumented = getBpMove(function);
        new_instr = IRDB_SDK::insertAssemblyInstructionsAfter(fileIr, instructionToBeInstrumented, instrumentation,
                                                              instrumentationParams);
    } else {
        instructionToBeInstrumented = function->getEntryPoint();
        new_instr = IRDB_SDK::insertAssemblyInstructionsBefore(fileIr, instructionToBeInstrumented, instrumentation,
                                                              instrumentationParams);
    }

    auto calls = DisassemblyService::getCallInstructionPosition(new_instr);
    for (auto call: calls) {
        new_instr[call]->setTarget(RuntimeLib::msan_poison_stack);
    }
}

/**
 *  Adds instrumentation to the input string after the function prologue to set the shadow
 *  of the stack frame to uninitialised.
 *
 * <pre> @code
 *    lower addresses
 *  ____________________
 * | alignment padding  |&lt;<- RSP
 * |____________________|     ||
 * |   local variable3  |     ||
 * |____________________|     ||
 * |   local variable2  |     ||    memory between new SP and BP should be uninit
 * |____________________|     ||
 * |  local variable1   |     ||
 * |____________________|     ||
 * | stored base pointer|&lt;<- RBP
 * |____________________|
 * |   return address   |
 * |____________________|
 *    higher addresses
 * </pre>
 * @param instrumentation string to which the instrumentation assembly will be added.
 */
void StackVariableHandler::poisonStackframe(string &instrumentation) {
    // Location of original stack pointer is off due to state keeping.
    // 0x80 for lea stack offset, 0x50 (80d) for 10x push of 8-byte registers
    instrumentation = instrumentation +
                      "lea rdi, [rsp + 0xd0]\n" +    // first argument
                      "mov rsi, %%1\n" +            // second argument
                      "call 0\n";
}

/**
 * Adds instrumentation to the input string to poison the red zone based on the address of the
 * stack pointer upon function entry.
 * @param instrumentation string to which the instrumentation assembly will be added.
 */
void StackVariableHandler::poisonRedZone(string &instrumentation) {
    // Location of original stack pointer is off due to state keeping.
    // + 0x80 for lea stack offset, + 0x50 (80d) for 10x push of 8-byte registers, again - 0x80 because we want
    // to poison the red zone below the stack pointer.
    instrumentation = instrumentation +
                      "lea rdi, [rsp + 50]\n" +    // first argument
                      "mov rsi, %%2\n" +           // second argument
                      "call 0\n";
}

/**
 * Returns the first <code>mov rbp, rsp</code> instruction in the function prologue.
 * @throws invalid_argument if there is no <code>mov rbp, rsp</code>.
 * @param function Function to be searched.
 * @return mov rbp, rsp instruction.
 */
IRDB_SDK::Instruction_t *StackVariableHandler::getBpMove(IRDB_SDK::Function_t *function) {
    auto instruction = function->getEntryPoint();
    auto decodedInstruction = IRDB_SDK::DecodedInstruction_t::factory(instruction);
    auto operands = decodedInstruction->getOperands();
    while (
            decodedInstruction->getMnemonic() != "mov" ||
            !operands[0]->isGeneralPurposeRegister() || operands[0]->getRegNumber() != RBP ||
            !operands[1]->isGeneralPurposeRegister() || operands[1]->getRegNumber() != RSP) {
        instruction = instruction->getFallthrough();
        if (instruction == nullptr) {
            throw std::invalid_argument("Function " + function->getName() + " does not set base pointer in prologue.");
        }
        decodedInstruction = IRDB_SDK::DecodedInstruction_t::factory(instruction);
        operands = decodedInstruction->getOperands();
    }
    return instruction;
}


/**
 * Returns the first <code>sub rsp, X</code> instruction in the function prologue.
 * @throws invalid_argument if there is no <code>sub rsp, X</code>.
 * @param function Function to be searched.
 * @return sub rsp, X instruction.
 */
IRDB_SDK::Instruction_t *StackVariableHandler::getSpSub(IRDB_SDK::Function_t *function) {
    auto instruction = function->getEntryPoint();
    auto decodedInstruction = IRDB_SDK::DecodedInstruction_t::factory(instruction);
    auto operands = decodedInstruction->getOperands();
    while (
            decodedInstruction->getMnemonic() != "sub" ||
            !operands[0]->isGeneralPurposeRegister() || operands[0]->getRegNumber() != RSP ||
            !operands[1]->isConstant()) {
        instruction = instruction->getFallthrough();
        if (instruction == nullptr) {
            throw std::invalid_argument("Function " + function->getName() + " does not adjust stack pointer in prologue.");
        }
        decodedInstruction = IRDB_SDK::DecodedInstruction_t::factory(instruction);
        operands = decodedInstruction->getOperands();
    }
    return instruction;
}
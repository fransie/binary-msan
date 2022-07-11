#include <irdb-transform>
#include "StackVariableHandler.h"
#include "RuntimeLib.h"
#include "Utils.h"
#include "CapstoneService.h"
#include "../common/RegisterNumbering.h"

using namespace std;

size_t RED_ZONE_SIZE = 128;

StackVariableHandler::StackVariableHandler(IRDB_SDK::FileIR_t *fileIr) : fileIr(fileIr){}

void StackVariableHandler::instrument(unique_ptr<FunctionAnalysis> &functionAnalysis) {
    // getStackFrameSize() looks for the first occurrence of a `sub rsp|esp, x` instruction and returns x
    auto function = functionAnalysis->getFunction();
    auto stackFrameSize = function->getStackFrameSize();
    bool hasStackPointerSub = (stackFrameSize != 0);
    bool canUseRedZone = functionAnalysis->isLeafOrTailCallFunction;

    if(!canUseRedZone && !hasStackPointerSub){
        // do nothing
        return;
    }

    string instrumentation = Utils::getPushCallerSavedRegistersInstrumentation();
    vector<basic_string<char>> instrumentationParams = vector<basic_string<char>>{"", "", ""};

    if(hasStackPointerSub){
        auto param = poisonStackframe(stackFrameSize, instrumentation);
        instrumentationParams[0] = param;
    }
    if(canUseRedZone){
        auto params = poisonRedZone(stackFrameSize, instrumentation);
        instrumentationParams[1] = params[0];
        instrumentationParams[2] = params[1];
    }
    instrumentation += Utils::getPopCallerSavedRegistersInstrumentation();

    auto movBpInstruction = getBpMove(function);
    const auto new_instr = IRDB_SDK::insertAssemblyInstructionsAfter(fileIr, movBpInstruction, instrumentation, instrumentationParams);
    auto calls = CapstoneService::getCallInstructionPosition(new_instr);
    for(auto call : calls){
        new_instr[call]->setTarget(RuntimeLib::__msan_poison_stack);
    }
}

/**
 *  Adds instrumentation after the function prologue (push rbp; mov rbp, rsp; sub rsp, X) to set the shadow
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
 * @param instruction function in which to insert the instrumentation
 */
basic_string<char> StackVariableHandler::poisonStackframe(int stackFrameSize, string &instrumentation) {
    instrumentation = instrumentation +
                            "lea rdi, [rbp - %%1]\n" +    // first argument
                            "mov rsi, %%1\n" +            // second argument
                            "call 0\n";
    return to_string(Utils::toHex(stackFrameSize));
}

vector<basic_string<char>> StackVariableHandler::poisonRedZone(int stackFrameSize, string &instrumentation) {
    int redZoneOffset = RED_ZONE_SIZE + stackFrameSize;
    instrumentation = instrumentation +
                             "lea rdi, [rbp - %%2]\n" +    // first argument
                             "mov rsi, %%3\n" +            // second argument
                             "call 0\n";
    return vector<basic_string<char>>({to_string(Utils::toHex(redZoneOffset)), to_string(Utils::toHex(RED_ZONE_SIZE))});
}

IRDB_SDK::Instruction_t* StackVariableHandler::getBpMove(IRDB_SDK::Function_t *function) {
    auto instruction = function->getEntryPoint();
    auto decodedInstruction = IRDB_SDK::DecodedInstruction_t::factory(instruction);
    auto operands = decodedInstruction->getOperands();
    while (
            decodedInstruction->getMnemonic() != "mov" ||
            !operands[0]->isGeneralPurposeRegister() || operands[0]->getRegNumber() != RBP ||
            !operands[1]->isGeneralPurposeRegister() || operands[1]->getRegNumber() != RSP)
    {
        instruction = instruction->getFallthrough();
        if(instruction == nullptr){
            throw std::invalid_argument("Function " + function->getName() + " does not set base pointer in prologue.");
        }
        decodedInstruction = IRDB_SDK::DecodedInstruction_t::factory(instruction);
        operands = decodedInstruction->getOperands();
    }
    return instruction;
}
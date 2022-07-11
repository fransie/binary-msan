#include <irdb-transform>
#include "StackVariableHandler.h"
#include "RuntimeLib.h"
#include "Utils.h"
#include "CapstoneService.h"

using namespace std;

size_t RED_ZONE_SIZE = 128;

StackVariableHandler::StackVariableHandler(IRDB_SDK::FileIR_t *fileIr) : fileIr(fileIr){}

void StackVariableHandler::instrument(IRDB_SDK::Function_t *function) {
    // getStackFrameSize() looks for the first occurrence of a `sub rsp|esp, x` instruction and returns x
    auto stackFrameSize = function->getStackFrameSize();
    bool hasStackPointerSub = (stackFrameSize != 0);
    bool canUseRedZone = isLeafOrTailCallFunction(function);

    if(!canUseRedZone && !hasStackPointerSub){
        // do nothing
        return;
    }

    string instrumentation = Utils::getPushCallerSavedRegistersInstrumentation();
    vector<basic_string<char>> instrumentationParams = vector<basic_string<char>>{};

    if(hasStackPointerSub){
        auto params = poisonStackframe(stackFrameSize, instrumentation);
        instrumentationParams.insert(end(instrumentationParams), begin(params), end(params));
    }
    if(canUseRedZone){
        auto params = poisonRedZone(0, instrumentation);
        instrumentationParams.insert(end(instrumentationParams), begin(params), end(params));
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
 * Checks whether the input function is a leaf function or uses a tail call by
 * looking for a <code>call</code> instruction.
 * @param function input function.
 * @return true if there is no <code>call</code> in the function.
 */
bool StackVariableHandler::isLeafOrTailCallFunction(IRDB_SDK::Function_t *function) {
    auto instructions = function->getInstructions();
    for(auto instruction : instructions){
        auto decodedInstruction = IRDB_SDK::DecodedInstruction_t::factory(instruction);
        if (decodedInstruction->getMnemonic() == "call"){
            return false;
        }
    }
    return true;
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
vector<basic_string<char>> StackVariableHandler::poisonStackframe(int stackFrameSize, string &instrumentation) {
    instrumentation = instrumentation +
                            "lea rdi, [rbp - %%1]\n" +    // first argument
                            "mov rsi, %%1\n" +            // second argument
                            "call 0\n";
    return vector<basic_string<char>>({to_string(Utils::toHex(stackFrameSize))});
}

vector<basic_string<char>> StackVariableHandler::poisonRedZone(int stackFrameSize, string &instrumentation) {
    instrumentation = instrumentation +
                             "lea rdi, [rbp - %%1]\n" +    // first argument
                             "mov rsi, %%2\n" +            // second argument
                             "call 0\n";
    return vector<basic_string<char>>({to_string(Utils::toHex(stackFrameSize)), to_string(Utils::toHex(RED_ZONE_SIZE))});
}

IRDB_SDK::Instruction_t* StackVariableHandler::getBpMove(IRDB_SDK::Function_t *function) {
    auto prologueStart = function->getEntryPoint();
    auto instruction = prologueStart;
    auto nextInstruction = instruction->getFallthrough();
    auto decodedNextInstruction = IRDB_SDK::DecodedInstruction_t::factory(nextInstruction);
    while (decodedNextInstruction->getMnemonic() != "sub"){
        instruction = nextInstruction;
        nextInstruction = instruction->getFallthrough();
        decodedNextInstruction = IRDB_SDK::DecodedInstruction_t::factory(nextInstruction);
    }
    return instruction;
}
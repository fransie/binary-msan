//
// Created by Franziska Mäckel on 30.06.22.
//

#include <irdb-transform>
#include "StackVariableHandler.h"
#include "RuntimeLib.h"
#include "Utils.h"

using namespace std;

StackVariableHandler::StackVariableHandler(IRDB_SDK::FileIR_t *fileIr) : fileIr(fileIr){}

void StackVariableHandler::instrument(IRDB_SDK::Function_t *function) {
    // getStackFrameSize() looks for the first occurence of a `sub rsp|esp, x` instruction and returns x
    auto stackFrameSize = function->getStackFrameSize();
    bool hasStackPointerSub = (stackFrameSize != 0);
    bool canUseRedZone = isLeafOrTailCallFunction(function);

    if(!canUseRedZone && !hasStackPointerSub){
        // Case 1
        return;
    }
    if(!canUseRedZone && hasStackPointerSub){
        // Case 2
        setLocalVariablesToUninit(function, stackFrameSize);
    } else if(canUseRedZone){
        // Cases 3 & 4
        if(hasStackPointerSub){
            // Case 4
        }
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
 * @param function function in which to insert the instrumentation
 */
void StackVariableHandler::setLocalVariablesToUninit(IRDB_SDK::Function_t *function, int stackFrameSize) {
    auto prologueStart = function->getEntryPoint();
    auto nextInstruction = prologueStart;
    auto nextDecodedInstruction = IRDB_SDK::DecodedInstruction_t::factory(nextInstruction);
    while (nextDecodedInstruction->getMnemonic() != "sub"){
        nextInstruction = nextInstruction->getFallthrough();
        nextDecodedInstruction = IRDB_SDK::DecodedInstruction_t::factory(nextInstruction);
    }

    string instrumentation = string() +
                             Utils::getPushCallerSavedRegistersInstrumentation() +
                             "mov rdi, rsp\n" +    // first argument
                             "mov rsi, %%1\n" +    // second argument
                             "call 0\n" +
                             Utils::getPopCallerSavedRegistersInstrumentation();
    vector<basic_string<char>> instrumentationParams {to_string(Utils::toHex(stackFrameSize))};
    const auto new_instr = IRDB_SDK::insertAssemblyInstructionsAfter(fileIr, nextInstruction, instrumentation, instrumentationParams);
    new_instr[13]->setTarget(RuntimeLib::__msan_poison_stack);
}




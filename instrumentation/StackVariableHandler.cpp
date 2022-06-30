//
// Created by Franziska Mäckel on 30.06.22.
//

#include "StackVariableHandler.h"

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
        setLocalVariablesToUninit(function);
    } else if(canUseRedZone){
        // Cases 3 & 4
        if(hasStackPointerSub){
            // Case 4
        }
    }
    // when should the call to my function occur? should not be before push rbp because this misalignes the stack
    // before or after `sub rsp, x`?

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

void StackVariableHandler::setLocalVariablesToUninit(IRDB_SDK::Function_t *function) {

}



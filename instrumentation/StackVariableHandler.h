//
// Created by Franziska Mäckel on 30.06.22.
//

#ifndef BINARY_MSAN_STACKVARIABLEHANDLER_H
#define BINARY_MSAN_STACKVARIABLEHANDLER_H

#include "FunctionHandler.h"

/**
 * TODO: document this
 *
 * | Case | Function type | Prologue    | Reaction                                                           |
 * | ---- | ------------- | ----------- | ------------------------------------------------------------------ |
 * | 1    | Non-leaf      | without sub | Nothing, no local variables                                        |
 * | 2    | Non-leaf      | with sub    | Uninit local variables based on stack pointer substraction         |
 * | 3    | Leaf/tail     | without sub | ???                |
 * | 4    | Leaf/tail     | with sub    | ??? |
 */
class StackVariableHandler : public FunctionHandler{
public:
    explicit StackVariableHandler(IRDB_SDK::FileIR_t *fileIr);
    void instrument(IRDB_SDK::Function_t *function) override;
private:
    IRDB_SDK::FileIR_t *fileIr;

    bool isLeafOrTailCallFunction(IRDB_SDK::Function_t *function);
    void setLocalVariablesToUninit(IRDB_SDK::Function_t *function, int stackFrameSize);
};


#endif //BINARY_MSAN_STACKVARIABLEHANDLER_H

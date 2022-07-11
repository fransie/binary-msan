
#ifndef BINARY_MSAN_STACKVARIABLEHANDLER_H
#define BINARY_MSAN_STACKVARIABLEHANDLER_H

#include "FunctionHandler.h"
#include "FunctionAnalysis.h"

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

    void instrument(std::unique_ptr<FunctionAnalysis> &functionAnalysis);

private:
    IRDB_SDK::FileIR_t *fileIr;

    IRDB_SDK::Instruction_t* getBpMove(IRDB_SDK::Function_t *function);
    std::vector<std::basic_string<char>> poisonRedZone(int stackFrameSize, std::string &instrumentation);
    std::basic_string<char> poisonStackframe(int stackFrameSize, std::string &instrumentation);
};


#endif //BINARY_MSAN_STACKVARIABLEHANDLER_H

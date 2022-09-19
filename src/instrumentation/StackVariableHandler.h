#ifndef BINARY_MSAN_STACKVARIABLEHANDLER_H
#define BINARY_MSAN_STACKVARIABLEHANDLER_H

#include "FunctionHandler.h"
#include "FunctionAnalysis.h"

/**
 * Handles the poisoning of stack variables before they are initialised upon function entry.
 *
 * | Case | Function type | Prologue    | Reaction                                                           |
 * | ---- | ------------- | ----------- | ------------------------------------------------------------------ |
 * | 1    | Non-leaf      | without sub | Nothing, no local variables                                        |
 * | 2    | Non-leaf      | with sub    | Poison local variables based on stack frame                         |
 * | 3    | Leaf/tail     | without sub | Poison red zone (128 bytes below stack pointer)                    |
 * | 4    | Leaf/tail     | with sub    | Poison both stack frame and red zone                               |
 */
class StackVariableHandler : public FunctionHandler {
public:
    explicit StackVariableHandler(IRDB_SDK::FileIR_t *fileIr);

    void instrument(std::unique_ptr<FunctionAnalysis> &functionAnalysis) override;

private:
    IRDB_SDK::FileIR_t *fileIr;

    static IRDB_SDK::Instruction_t *getBpMove(IRDB_SDK::Function_t *function);
    static std::vector<std::basic_string<char>> poisonRedZone(int stackFrameSize, std::string &instrumentation);
    static std::basic_string<char> poisonStackframe(int stackFrameSize, std::string &instrumentation);
};


#endif //BINARY_MSAN_STACKVARIABLEHANDLER_H

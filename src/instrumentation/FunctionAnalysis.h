#ifndef BINARY_MSAN_FUNCTIONANALYSIS_H
#define BINARY_MSAN_FUNCTIONANALYSIS_H

#include <irdb-core>

class FunctionAnalysis {
public:
    explicit FunctionAnalysis(IRDB_SDK::Function_t *function);
    ~FunctionAnalysis() = default;

    bool isLeafOrTailCallFunction;

    IRDB_SDK::Function_t *getFunction() const;
private:
    IRDB_SDK::Function_t *function;

    void analyse();
};
#endif //BINARY_MSAN_FUNCTIONANALYSIS_H

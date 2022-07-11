//
// Created by Franziska Mäckel on 30.06.22.
//

#ifndef BINARY_MSAN_FUNCTIONHANDLER_H
#define BINARY_MSAN_FUNCTIONHANDLER_H

#include <irdb-core>
#include "FunctionAnalysis.h"

class FunctionHandler {
public:
    virtual void instrument(std::unique_ptr<FunctionAnalysis> &functionAnalysis) = 0;
};


#endif //BINARY_MSAN_FUNCTIONHANDLER_H

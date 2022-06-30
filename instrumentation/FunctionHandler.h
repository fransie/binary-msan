//
// Created by Franziska Mäckel on 30.06.22.
//

#ifndef BINARY_MSAN_FUNCTIONHANDLER_H
#define BINARY_MSAN_FUNCTIONHANDLER_H

#include <irdb-core>

class FunctionHandler {
public:
    virtual void instrument(IRDB_SDK::Function_t *function) = 0;
};


#endif //BINARY_MSAN_FUNCTIONHANDLER_H

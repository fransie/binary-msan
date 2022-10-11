#ifndef BINARY_MSAN_INSTRCOUNTER_H
#define BINARY_MSAN_INSTRCOUNTER_H

#include <irdb-core>
#include <irdb-transform>

class InstrCounter : protected IRDB_SDK::Transform_t {
public:
    explicit InstrCounter(IRDB_SDK::FileIR_t *fileIR);
    bool executeStep();

    bool parseArgs(std::vector<std::string> step_args) {filename = step_args[0]; return true;}
private:
    std::string filename;
};


#endif //BINARY_MSAN_INSTRCOUNTER_H

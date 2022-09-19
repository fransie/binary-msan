#ifndef BINARY_MSAN_UTILS_H
#define BINARY_MSAN_UTILS_H

class Utils {
public:
    static std::string getStateSavingInstrumentation();
    static std::string getStateRestoringInstrumentation();
    static unsigned int toHex(int num);
};

#endif //BINARY_MSAN_UTILS_H

#ifndef BINARY_MSAN_UTILS_H
#define BINARY_MSAN_UTILS_H

#include <iostream>
#include <sstream>

class Utils {
public:
    static std::string getPushCallerSavedRegistersInstrumentation();
    static std::string getPopCallerSavedRegistersInstrumentation();
    static unsigned int toHex(int num);
};

#endif //BINARY_MSAN_UTILS_H
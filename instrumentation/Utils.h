//
// Created by Franziska Mäckel on 12.04.22.
//

#ifndef BINARY_MSAN_UTILS_H
#define BINARY_MSAN_UTILS_H

#include <iostream>

class Utils {
public:
    static std::string getPushCallerSavedRegistersInstrumentation();
    static std::string getPopCallerSavedRegistersInstrumentation();
    };


#endif //BINARY_MSAN_UTILS_H
project(test)
find_package(GTest CONFIG REQUIRED)

add_executable (unit_tests
        checkRegIsInitTests.cpp
        getRegisterShadowTests.cpp
        isRegFullyDefined.cpp
        isMemFullyDefined.cpp
        isRegOrRegFullyDefined.cpp
        isRegOrMemFullyDefined.cpp
        memToRegShadowCopyTests.cpp
        propagateMemOrRegShadow.cpp
        propagateRegOrMemShadow.cpp
        propagateRegOrRegShadow.cpp
        regToMemShadowCopyTests.cpp
        regToRegShadowCopyTests.cpp
        setMemShadowTests.cpp
        setRegShadowTests.cpp
        unpoisonUpper4BytesTests.cpp
        )


target_compile_options(unit_tests PUBLIC ${MSAN_CFLAGS} -fsanitize-recover=memory)

set(gtest_SOURCE_DIR "/home/franzi/Documents/googletest/googletest")
include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})

add_library(libcxx SHARED IMPORTED)
set_property(TARGET libcxx PROPERTY IMPORTED_LOCATION "${MSANIFIED_LLVM_DIR}/lib/libc++.so.1")

add_library(libcxxabi SHARED IMPORTED)
set_property(TARGET libcxxabi PROPERTY IMPORTED_LOCATION "${MSANIFIED_LLVM_DIR}/lib/libc++abi.so.1")

target_link_libraries(unit_tests gtest gtest_main pthread interface_msanified libcxx libcxxabi)
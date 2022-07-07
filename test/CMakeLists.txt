project(test)
find_package(GTest CONFIG REQUIRED)

add_executable (unit_tests
        getRegisterShadowTests.cpp
        isRegFullyDefined.cpp
        isMemFullyDefined.cpp
        isRegOrRegFullyDefined.cpp
        isRegOrMemFullyDefined.cpp
        setMemShadowTests.cpp
        setRegShadowTests.cpp
#        immToMem_16bit.cpp
#        immToMem_32bit.cpp
#        immToMem_64bit.cpp
#        memToReg_8bit.cpp
#        memToReg_8bitHigh.cpp
#        memToReg_16bit.cpp
#        memToReg_32bit.cpp
#        memToReg_64bit.cpp
#        regToMem_8bit.cpp
#        regToMem_8bitHigh.cpp
#        regToMem_16bit.cpp
#        regToMem_32bit.cpp
#        regToMem_64bit.cpp
#        stack_leaf.cpp
#        stack_regular.cpp
#        stack_tailcall.cpp
#        trap_conditional_branch.cpp
#        trap_pointer_deref.cpp
#        trap_syscall.cpp
        )


set(MSANIFIED_LLVM_DIR "/home/franzi/Documents/llvm-project-llvmorg-13.0.1/llvmInstrumentedBuild")
set(MSAN_CFLAGS -stdlib=libc++ -fsanitize=memory -L${MSANIFIED_LLVM_DIR}/lib -lc++ -lc++abi -I${MSANIFIED_LLVM_DIR}/include -I${MSANIFIED_LLVM_DIR}/include/c++/v1)
target_compile_options(unit_tests PUBLIC ${MSAN_CFLAGS} )

set(gtest_SOURCE_DIR "/home/franzi/Documents/googletest/googletest")
include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})

add_library(libcxx SHARED IMPORTED)
set_property(TARGET libcxx PROPERTY IMPORTED_LOCATION "${MSANIFIED_LLVM_DIR}/lib/libc++.so.1")

add_library(libcxxabi SHARED IMPORTED)
set_property(TARGET libcxxabi PROPERTY IMPORTED_LOCATION "${MSANIFIED_LLVM_DIR}/lib/libc++abi.so.1")

target_link_libraries(unit_tests gtest gtest_main pthread interface libcxx libcxxabi)
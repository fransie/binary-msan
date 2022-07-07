############### RUNTIME LIBRARY ###############

add_library(interface SHARED
        Interface.cpp
        Interface.h
        ../common/Width.h
)
# TODO: only add MSAN_CFLAGS this if needed for tests
target_compile_options(interface PUBLIC ${MSAN_CFLAGS})
target_compile_options(interface PRIVATE -Wextra -Wpedantic)

# collect include directories
set(MSAN_INCLUDE_DIRS)
list(APPEND MSAN_INCLUDE_DIRS "/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/include/sanitizer/")
list(APPEND MSAN_INCLUDE_DIRS "/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/lib/msan/")
list(APPEND MSAN_INCLUDE_DIRS "/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/lib/")

# add imported targets for msan and msan_cxx
add_library(msan SHARED IMPORTED)
set_property(TARGET msan PROPERTY IMPORTED_LOCATION "/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compilerRT-build/lib/linux/libclang_rt.msan-x86_64.so")
target_include_directories(msan INTERFACE ${MSAN_INCLUDE_DIRS})

add_library(msan_cxx SHARED IMPORTED)
set_property(TARGET msan_cxx PROPERTY IMPORTED_LOCATION "/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compilerRT-build/lib/linux/libclang_rt.msan_cxx-x86_64.so")
target_include_directories(msan_cxx INTERFACE ${MSAN_INCLUDE_DIRS})


# add msan libs to runtime library target
target_link_libraries(
        interface msan msan_cxx
)
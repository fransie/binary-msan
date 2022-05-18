############### INSTRUMENTATION ###############
add_executable(binmsan
        msan.cpp
        main.cpp
        CapstoneService.cpp
        utils.cpp
)
target_compile_options(binmsan PRIVATE -Wall -Wextra -Wpedantic)

# add irdb_sdk to instrumentation target
target_link_libraries(
        binmsan PRIVATE irdb-sdk
)

# the .exe postfix is required by the zipr framework
set_target_properties(binmsan PROPERTIES OUTPUT_NAME "binmsan.exe")


############### RUNTIME LIBRARY ###############

add_library(interface SHARED
        interface.cpp
)
target_compile_options(interface PRIVATE -Wall -Wextra -Wpedantic)

# collect include directories in a list
set(MSAN_INCLUDE_DIRS)
list(APPEND MSAN_INCLUDE_DIRS "/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/include/sanitizer/")
list(APPEND MSAN_INCLUDE_DIRS "/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/lib/msan/")
list(APPEND MSAN_INCLUDE_DIRS "/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/lib/")

# add imported targets for msan and msan_cxx
add_library(msan SHARED IMPORTED "/home/franzi/Documents/llvm-project-llvmorg-13.0.1/compiler-rt/include/sanitizer/")
set_property(TARGET msan PROPERTY IMPORTED_LOCATION "/home/franzi/Documents/llvm-project-llvmorg-13.0.1/buildcompilerRT/lib/linux/libclang_rt.msan-x86_64.so")
target_include_directories(msan INTERFACE ${MSAN_INCLUDE_DIRS})

add_library(msan_cxx SHARED IMPORTED)
set_property(TARGET msan_cxx PROPERTY IMPORTED_LOCATION "/home/franzi/Documents/llvm-project-llvmorg-13.0.1/buildcompilerRT/lib/linux/libclang_rt.msan_cxx-x86_64.so")
target_include_directories(msan_cxx INTERFACE ${MSAN_INCLUDE_DIRS})

# add msan libs to runtime library target
target_link_libraries(
        interface msan msan_cxx
)
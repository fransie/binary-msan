add_library(interface SHARED
        interface.cpp
        )

add_executable(binmsan
        msan.cpp
        interface.cpp
        main.cpp
        CapstoneService.cpp
        utils.cpp
        )
# the .exe postfix is required by the zipr framework
set_target_properties(binmsan PROPERTIES OUTPUT_NAME "binmsan.exe")

target_compile_options(binmsan PRIVATE -Wall -Wextra -Wpedantic)
target_compile_options(interface PRIVATE -Wall -Wextra -Wpedantic)

target_link_libraries(
        binmsan PRIVATE irdb-sdk
        )

add_library(msan SHARED IMPORTED)
set_property(TARGET msan PROPERTY IMPORTED_LOCATION "/home/franzi/Documents/llvm-project-llvmorg-13.0.1/buildcompilerRT/lib/linux/libclang_rt.msan-x86_64.so")
add_library(msan_cxx SHARED IMPORTED)
set_property(TARGET msan_cxx PROPERTY IMPORTED_LOCATION "/home/franzi/Documents/llvm-project-llvmorg-13.0.1/buildcompilerRT/lib/linux/libclang_rt.msan_cxx-x86_64.so")

target_link_libraries(
        interface msan msan_cxx
)
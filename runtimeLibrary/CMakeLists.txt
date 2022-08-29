############### RUNTIME LIBRARY ###############

add_library(interface SHARED
        Interface.cpp
        Interface.h
        ../common/Width.h
)
target_compile_options(interface PRIVATE -Wextra -Wpedantic)

# collect include directories
set(MSAN_INCLUDE_DIRS)
list(APPEND MSAN_INCLUDE_DIRS "$ENV{BINMSAN_HOME}/llvm_shared_msan_lib/compiler-rt/include/sanitizer/")
list(APPEND MSAN_INCLUDE_DIRS "$ENV{BINMSAN_HOME}/llvm_shared_msan_lib/compiler-rt/lib/msan/")
list(APPEND MSAN_INCLUDE_DIRS "$ENV{BINMSAN_HOME}/llvm_shared_msan_lib/compiler-rt/lib/")

# add imported targets for msan and msan_cxx
add_library(msan SHARED IMPORTED)
set_property(TARGET msan PROPERTY IMPORTED_LOCATION "$ENV{BINMSAN_HOME}/llvm_shared_msan_lib/libclang_rt.msan-x86_64.so")
target_include_directories(msan INTERFACE ${MSAN_INCLUDE_DIRS})

add_library(msan_cxx SHARED IMPORTED)
set_property(TARGET msan_cxx PROPERTY IMPORTED_LOCATION "$ENV{BINMSAN_HOME}/llvm_shared_msan_lib/libclang_rt.msan_cxx-x86_64.so")
target_include_directories(msan_cxx INTERFACE ${MSAN_INCLUDE_DIRS})


# add msan libs to runtime library target
target_link_libraries(
        interface msan msan_cxx
)

######### BEGIN UNCOMMENT UNIT TESTS #########

# set(MSAN_CFLAGS -stdlib=libc++ -fsanitize=memory -L${MSANIFIED_LLVM_DIR}/lib -lc++ -lc++abi -I${MSANIFIED_LLVM_DIR}/include -I${MSANIFIED_LLVM_DIR}/include/c++/v1)

## Use this target for the unit tests to avoid false positives from uninstrumented code.
#add_library(interface_msanified SHARED
#        Interface.cpp
#        Interface.h
#        ../common/RegisterNumbering.h
#        ../common/Width.h
#        )
#
#target_compile_options(interface_msanified PUBLIC ${MSAN_CFLAGS})
#
## add msan libs to runtime library target
#target_link_libraries(
#        interface_msanified msan msan_cxx
#)
######### END UNCOMMENT UNIT TESTS #########
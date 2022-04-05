add_library(msan SHARED
        eflags_access.cpp
        eflags_access.hpp
        jumps.cpp
        jumps.hpp
        msan.cpp
        msan.hpp
        msan_driver.cpp
        )

target_link_libraries(
        msan PRIVATE irdb-sdk
        )

add_library(msan SHARED
        eflags_access.cpp
        eflags_access.hpp
        jumps.cpp
        jumps.hpp

        )

target_link_libraries(
        msan PRIVATE irdb-sdk
        )

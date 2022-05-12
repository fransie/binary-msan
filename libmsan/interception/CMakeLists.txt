# Build for the runtime interception helper library.

add_library(interception STATIC
  interception_linux.cpp
  interception_mac.cpp
  interception_win.cpp
  interception_type_test.cpp
  interception.h
  interception_linux.h
  interception_mac.h
  interception_win.h
  )

# TODO: maybe delete?
target_link_libraries(interception
        PRIVATE ${CMAKE_DL_LIBS}
)

set(MSAN_CFLAGS -Wall -W -Wno-unused-parameter -Wwrite-strings -pedantic -Wno-long-long  -fPIC -fno-builtin -fno-exceptions -fno-rtti -fomit-frame-pointer -funwind-tables -fvisibility=hidden -Wno-variadic-macros)
target_compile_options(interception INTERFACE ${MSAN_CFLAGS})
target_include_directories(interception PUBLIC ..)

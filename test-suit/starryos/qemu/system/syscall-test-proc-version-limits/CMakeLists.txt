cmake_minimum_required(VERSION 3.20)
project(test-proc-version-limits C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_executable(test-proc-version-limits src/main.c)
target_include_directories(test-proc-version-limits PRIVATE src)
target_compile_options(test-proc-version-limits PRIVATE -Wall -Wextra -Werror)

install(TARGETS test-proc-version-limits RUNTIME DESTINATION usr/bin/starry-test-suit)

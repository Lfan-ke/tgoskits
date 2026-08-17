cmake_minimum_required(VERSION 3.20)
project(test-sem C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_executable(test-sem src/main.c)
target_include_directories(test-sem PRIVATE src)
target_compile_options(test-sem PRIVATE -Wall -Wextra -Werror)

install(TARGETS test-sem RUNTIME DESTINATION usr/bin/starry-test-suit)

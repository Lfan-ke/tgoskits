cmake_minimum_required(VERSION 3.20)
project(test-readahead C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_executable(test-readahead src/main.c)
target_include_directories(test-readahead PRIVATE src)
target_compile_options(test-readahead PRIVATE -Wall -Wextra -Werror)

install(TARGETS test-readahead RUNTIME DESTINATION usr/bin/starry-test-suit)

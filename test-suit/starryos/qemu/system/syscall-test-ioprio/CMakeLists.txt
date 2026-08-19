cmake_minimum_required(VERSION 3.20)
project(test-ioprio C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_executable(test-ioprio src/main.c)
target_include_directories(test-ioprio PRIVATE src)
target_compile_options(test-ioprio PRIVATE -Wall -Wextra -Werror)

install(TARGETS test-ioprio RUNTIME DESTINATION usr/bin/starry-test-suit)

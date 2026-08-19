cmake_minimum_required(VERSION 3.20)

project(test-vmsplice-tee C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_executable(test-vmsplice-tee src/main.c)
include_directories(test-vmsplice-tee PRIVATE src)
target_compile_options(test-vmsplice-tee PRIVATE -Wall -Wextra -Werror)

install(TARGETS test-vmsplice-tee RUNTIME DESTINATION usr/bin/starry-test-suit)

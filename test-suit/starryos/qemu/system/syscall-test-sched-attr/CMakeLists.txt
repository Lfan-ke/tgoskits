cmake_minimum_required(VERSION 3.20)
project(test-sched-attr C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_executable(test-sched-attr src/main.c)
target_include_directories(test-sched-attr PRIVATE src)
target_compile_options(test-sched-attr PRIVATE -Wall -Wextra -Werror)

install(TARGETS test-sched-attr RUNTIME DESTINATION usr/bin/starry-test-suit)

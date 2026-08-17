cmake_minimum_required(VERSION 3.20)
project(test-mlockall C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_executable(test-mlockall src/main.c)
target_include_directories(test-mlockall PRIVATE src)
target_compile_options(test-mlockall PRIVATE -Wall -Wextra -Werror)

install(TARGETS test-mlockall RUNTIME DESTINATION usr/bin/starry-test-suit)

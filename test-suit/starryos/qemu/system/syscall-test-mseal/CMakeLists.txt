cmake_minimum_required(VERSION 3.20)
project(test-mseal C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_executable(test-mseal src/main.c)
target_compile_options(test-mseal PRIVATE -Wall -Wextra)
target_link_options(test-mseal PRIVATE -static)

install(TARGETS test-mseal RUNTIME DESTINATION usr/bin/starry-test-suit)

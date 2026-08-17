cmake_minimum_required(VERSION 3.20)
project(test-clock-settime C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_executable(test-clock-settime src/main.c)
target_include_directories(test-clock-settime PRIVATE src)
target_compile_options(test-clock-settime PRIVATE -Wall -Wextra -Werror)

install(TARGETS test-clock-settime RUNTIME DESTINATION usr/bin/starry-test-suit)

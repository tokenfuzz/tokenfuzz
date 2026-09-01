cmake_minimum_required(VERSION 3.16)
project(gauge C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_executable(gauge src/gauge.c src/gauge_cli.c)
target_include_directories(gauge PRIVATE include)

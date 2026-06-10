cmake_minimum_required(VERSION 3.16)
project(canary C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Asserts stay enabled on purpose; see .audit/build.sh.
add_executable(canary src/canary.c)
target_include_directories(canary PRIVATE src)

cmake_minimum_required(VERSION 3.16)
project(chtio C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Asserts stay enabled on purpose; see .audit/build.sh — the TRAIL field's
# debug invariant relies on assert() firing rather than being compiled out.
add_executable(chtio src/chtio.c src/chtio_cli.c)
target_include_directories(chtio PRIVATE include)

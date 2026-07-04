cmake_minimum_required(VERSION 3.16)
project(rcfg C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Asserts stay enabled on purpose; see .audit/build.sh — the CHECK field's
# debug invariant relies on assert() firing rather than being compiled out.
add_executable(rcfg src/rcfg.c src/rcfg_cli.c)
target_include_directories(rcfg PRIVATE include)

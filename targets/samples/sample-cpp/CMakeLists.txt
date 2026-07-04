cmake_minimum_required(VERSION 3.16)
project(rbundle CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Asserts stay enabled on purpose; see .audit/build.sh — the CHECK field's
# debug invariant relies on assert() firing rather than being compiled out.
add_executable(rbundle src/rbundle.cpp src/rbundle_cli.cpp)
target_include_directories(rbundle PRIVATE include)

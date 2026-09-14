cmake_minimum_required(VERSION 3.16)
project(rcfg C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Both ordinary Debug and Release configurations are supported. The audit
# sanitizer recipe uses Debug so invariant failures remain visible at runtime.
add_executable(rcfg src/rcfg.c src/rcfg_cli.c)
target_include_directories(rcfg PRIVATE include)

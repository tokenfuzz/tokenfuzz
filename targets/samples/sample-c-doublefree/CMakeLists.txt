cmake_minimum_required(VERSION 3.16)
project(chtio C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Both ordinary Debug and Release configurations are supported. The audit
# sanitizer recipe uses Debug so invariant failures remain visible at runtime.
add_executable(chtio src/chtio.c src/chtio_cli.c)
target_include_directories(chtio PRIVATE include)

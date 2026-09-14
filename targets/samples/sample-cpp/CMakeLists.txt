cmake_minimum_required(VERSION 3.16)
project(rbundle CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Both ordinary Debug and Release configurations are supported. The audit
# sanitizer recipe uses Debug so invariant failures remain visible at runtime.
add_executable(rbundle src/rbundle.cpp src/rbundle_cli.cpp)
target_include_directories(rbundle PRIVATE include)

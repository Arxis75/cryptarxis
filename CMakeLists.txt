cmake_minimum_required(VERSION 3.0.0)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

project(cryptarxis VERSION 1.0)

include_directories(${CMAKE_SOURCE_DIR}/src)

# Dependencies:
    # openssl
    # ethash
    # givaro
    # gmp

enable_testing()

add_subdirectory(src)
add_subdirectory(ethash)
add_subdirectory(tests)
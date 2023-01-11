cmake_minimum_required(VERSION 3.22.1)

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -D_GLIBCXX_DEBUG")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

project(myProject VERSION 1.0)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)

# Dependencies:
    # openssl
    # ethash
    # givaro
    # gmp

enable_testing()

add_subdirectory(tests)
add_subdirectory(src)
add_subdirectory(ethash)
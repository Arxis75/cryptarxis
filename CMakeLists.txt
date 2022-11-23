cmake_minimum_required(VERSION 3.0.0)

project(cryptarxis VERSION 1.0)

include_directories(${CMAKE_SOURCE_DIR}/src)

# openssl
# ethash
# givaro
# gmp

add_subdirectory(src)
add_subdirectory(ethash)
cmake_minimum_required(VERSION 3.22.1)

project(cryptarxis VERSION 1.0)

include_directories(${CMAKE_SOURCE_DIR}/src)

add_subdirectory(src)
add_subdirectory(ethash)
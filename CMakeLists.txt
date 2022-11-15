cmake_minimum_required(VERSION 3.22.1)

project(cryptarxis VERSION 1.0)

#include_directories(${cryptarxis_SOURCE_DIR})

file(GLOB HEADERS "*.h")
file(GLOB SOURCES "*.cpp")

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

add_executable(cryptarxis ${HEADERS} ${SOURCES})

#add_subdirectory(ethash)
add_subdirectory(crypto)

#target_link_libraries(cryptarxis PUBLIC OpenSSL::Crypto givaro ethash::ethash)
target_link_libraries(cryptarxis PUBLIC OpenSSL::Crypto ethash::ethash givaro)
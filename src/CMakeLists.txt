file(GLOB SOURCES "*.cpp")
file(GLOB COMMON "Common.cpp")

add_executable(cryptarxis ${SOURCES})

find_library(gmp gmp)
if(NOT gmp)
  message(FATAL_ERROR "gmp not found")
endif()

find_library(givaro givaro)
if(NOT givaro)
  message(FATAL_ERROR "givaro not found")
endif()

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

#include(FetchContent)
#FetchContent_Declare(reactor
#  GIT_REPOSITORY    https://github.com/Arxis75/reactor.git
#  GIT_TAG           origin/main     #latest commit
#  #GIT_TAG           v0.02          #stable commmit
#)
#FetchContent_MakeAvailable(reactor)

add_subdirectory(tools)
add_subdirectory(crypto)
add_subdirectory(reactor)

target_include_directories(lib_reactor PUBLIC ${reactor_SOURCE_DIR}/src)
target_link_libraries(cryptarxis PUBLIC OpenSSL::Crypto ethash::ethash gmp givaro lib_reactor)

target_sources(cryptarxis_tests PUBLIC ${COMMON})
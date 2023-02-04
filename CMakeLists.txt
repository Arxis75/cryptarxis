cmake_minimum_required(VERSION 3.18.4)

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -D_GLIBCXX_DEBUG")

set(CMAKE_CXX_STANDARD 20)          #use of time_since_epoch()
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

project(myProject VERSION 1.0)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)

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

include(FetchContent)
FetchContent_Declare(reactor
  GIT_REPOSITORY    https://github.com/Arxis75/reactor.git
  GIT_TAG           origin/main     #latest commit
  #GIT_TAG           v0.02          #stable commmit
)
FetchContent_MakeAvailable(reactor)

enable_testing()

add_subdirectory(tests)
add_subdirectory(src)
add_subdirectory(ethash)
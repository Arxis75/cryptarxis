file(GLOB SOURCES "*.cpp")
file(GLOB COMMON "Common.cpp")

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

add_executable(cryptarxis ${SOURCES})

include(FetchContent)
FetchContent_Declare(reactor
  GIT_REPOSITORY    https://github.com/Arxis75/reactor.git
  GIT_TAG           origin/main     #latest commit
  #GIT_TAG           v0.02          #stable commmit
)
FetchContent_MakeAvailable(reactor)

add_subdirectory(crypto)
add_subdirectory(tools)

target_include_directories(lib_reactor PUBLIC ${reactor_SOURCE_DIR}/src)
target_link_libraries(cryptarxis PUBLIC OpenSSL::Crypto ethash::ethash givaro lib_reactor)

target_sources(cryptarxis_tests PUBLIC ${COMMON})
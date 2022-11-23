file(GLOB SOURCES "*.cpp")

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

add_executable(cryptarxis ${SOURCES})

add_subdirectory(crypto)

target_link_libraries(cryptarxis PUBLIC OpenSSL::Crypto ethash::ethash givaro)
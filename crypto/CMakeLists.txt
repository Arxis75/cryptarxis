file(GLOB HEADERS "*.h")
file(GLOB SOURCES "*.cpp")

add_subdirectory(secp256k1)
add_subdirectory(ethash)

target_sources(cryptarxis PUBLIC ${HEADERS} ${SOURCES})
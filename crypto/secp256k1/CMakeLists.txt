file(GLOB HEADERS "*.h")
file(GLOB SOURCES "*.cpp")

target_sources(cryptarxis PUBLIC ${HEADERS} ${SOURCES})
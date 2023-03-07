file(GLOB SOURCES "*.cpp")
file(GLOB COMMON "Common.cpp")

add_executable(cryptarxis ${SOURCES})

add_subdirectory(tools)
add_subdirectory(crypto)
add_subdirectory(p2p)
#add_subdirectory(reactor)

#Libraries/Package declaration in root MakeFile!

#Remember to add lib_reactor to the following line of /tests/CMakeLists.txt !!
#target_include_directories(cryptarxis_tests PUBLIC ${reactor_SOURCE_DIR}/src)
#target_link_libraries(cryptarxis_tests PUBLIC [...] lib_reactor PRIVATE GTest::gtest)

target_include_directories(cryptarxis PUBLIC ${reactor_SOURCE_DIR}/src)  #Mandatory For library use in cryptarxis

#To allow gtest friend declarations, add: PRIVATE GTest::gtest
target_link_libraries(cryptarxis PUBLIC OpenSSL::Crypto ethash::ethash gmp givaro lib_reactor)

target_sources(cryptarxis_tests PUBLIC ${COMMON})
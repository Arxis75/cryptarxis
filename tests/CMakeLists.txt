# Download and unpack googletest at configure time
configure_file(CMakeLists.txt.in googletest-download/CMakeLists.txt)
execute_process(COMMAND "${CMAKE_COMMAND}" -G "${CMAKE_GENERATOR}" .
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests/googletest-download"
)
execute_process(COMMAND "${CMAKE_COMMAND}" --build .
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests/googletest-download"
)

# Add googletest directly to our build. This adds the following targets:
# gtest, gtest_main, gmock and gmock_main
add_subdirectory("${CMAKE_BINARY_DIR}/googletest-src" "${CMAKE_BINARY_DIR}/googletest-build")

add_executable(cryptarxis_tests main.cpp)

#Libraries/Package declaration in root MakeFile!
#Mandatory For reactor library use in cryptarxis_test:
target_include_directories(cryptarxis_tests PUBLIC ${reactor_SOURCE_DIR}/src)  #Mandatory For library use in cryptarxis
target_link_libraries(cryptarxis_tests PUBLIC OpenSSL::Crypto ethash::ethash gmp givaro lib_reactor PRIVATE GTest::gtest)

add_subdirectory(unit_tests)

include(GoogleTest)
gtest_discover_tests(cryptarxis_tests)
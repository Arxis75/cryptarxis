#include <gtest/gtest.h>
#include <Common.h>

TEST(RLPTests, TestRLP_nonEncodingConstructors)
{
    ByteStream expected;
    RLPByteStream actual;
    ASSERT_EQ(actual, expected);

    RLPByteStream expected_rlp;
    actual = RLPByteStream(expected_rlp);
    ASSERT_EQ(actual, expected_rlp);

    uint8_t array[3] = {0x01, 0x02, 0x03};
    expected = ByteStream(array, sizeof(array));
    actual = RLPByteStream(array, sizeof(array));
    ASSERT_EQ(actual, expected);

    const char* str = "0xf873010184583702008506bcfcef3a8252089429eca176157ba854c2dd7a14a2"
                      "7b4a253c8a01c9884639df38ec69f3bc80c001a0da23340cb8a3e75917bfc2a3"
                      "cb3685046ee3bdb8527bb0b3f455baafba235ce4a01d2bb7a39793211811face"
                      "204c35fa9de11229b93f3a300f0c512ec8ffd11a31";
    expected = ByteStream(str, strlen(str)>1, 16);
    actual = RLPByteStream(str);
    ASSERT_EQ(actual, expected);
}

TEST(RLPTests, TestRLP_EncodingConstructors)
{
    // Encoding empty RLP with as_list = false
    ByteStream expected("0x80", 1, 16);
    RLPByteStream actual(ByteStream(), false);
    ASSERT_EQ(actual, expected);

    // Encoding empty RLP with as_list = true
    expected = ByteStream("0xC0", 1, 16);
    actual = RLPByteStream(ByteStream(), true);
    ASSERT_EQ(actual, expected);

    // Encoding 1-byte ByteStream with as_list = false
    expected = ByteStream("0x01", 1, 16);
    actual = RLPByteStream(ByteStream(0x01), false);
    ASSERT_EQ(actual, expected);

    // Encoding 1-byte ByteStream with as_list = true
    expected = ByteStream("0xC101", 2, 16);
    actual = RLPByteStream(ByteStream(0x01), true);
    ASSERT_EQ(actual, expected);

    // Encoding 1-byte ByteStream with as_list = false
    expected = ByteStream("0x8181", 2, 16);
    actual = RLPByteStream(ByteStream(0x81), false);
    ASSERT_EQ(actual, expected);

    // Encoding 1-byte ByteStream with as_list = true
    // NOTA: the input here is an invalid RLP element
    // NOTA: It is up to the program to build valid RLP input
    // NOTA: before inclusion in a list
    expected = ByteStream("0xC181", 2, 16);
    actual = RLPByteStream(ByteStream(0x81), true);
    ASSERT_EQ(actual, expected);

    // Encoding 1-byte ByteStream with as_list = false
    expected = ByteStream("0x81B8", 2, 16);
    actual = RLPByteStream(ByteStream(0xB8), false);
    ASSERT_EQ(actual, expected);

    // Encoding 1-byte ByteStream with as_list = true
    // NOTA: the input here is an invalid RLP element
    // NOTA: It is up to the program to build valid RLP input
    // NOTA: before inclusion in a list
    expected = ByteStream("0xC1B8", 2, 16);
    actual = RLPByteStream(ByteStream(0xB8), true);
    ASSERT_EQ(actual, expected);

    // Encoding 1-byte ByteStream with as_list = false
    expected = ByteStream("0x81C1", 2, 16);
    actual = RLPByteStream(ByteStream(0xC1), false);
    ASSERT_EQ(actual, expected);

    // Encoding 1-byte ByteStream with as_list = true
    // NOTA: the input here is an invalid RLP element
    // NOTA: It is up to the program to build valid RLP input
    // NOTA: before inclusion in a list
    expected = ByteStream("0xC1C1", 2, 16);
    actual = RLPByteStream(ByteStream(0xC1), true);
    ASSERT_EQ(actual, expected);

    // Encoding 1-byte ByteStream with as_list = false
    expected = ByteStream("0x81F8", 2, 16);
    actual = RLPByteStream(ByteStream(0xF8), false);
    ASSERT_EQ(actual, expected);

    // Encoding 1-byte ByteStream with as_list = true
    // NOTA: the input here is an invalid RLP element
    // NOTA: It is up to the program to build valid RLP input
    // NOTA: before inclusion in a list
    expected = ByteStream("0xC1F8", 2, 16);
    actual = RLPByteStream(ByteStream(0xF8), true);
    ASSERT_EQ(actual, expected);

    // Encoding 55 bytes RLP with as_list = false
    expected = ByteStream("0xB7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                          "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 56, 16);
    actual = RLPByteStream(ByteStream("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 55, 16), false);
    ASSERT_EQ(actual, expected);

    // Encoding 55 bytes RLP with as_list = true
    // NOTA: the input here is an invalid RLP element
    // NOTA: It is up to the program to build valid RLP input
    // NOTA: before inclusion in a list
    expected = ByteStream("0xF7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                          "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 56, 16);
    actual = RLPByteStream(ByteStream("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 55, 16), true);
    ASSERT_EQ(actual, expected);

    // Encoding 56 bytes RLP with as_list = false
    expected = ByteStream("0xB838FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                          "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 58, 16);
    actual = RLPByteStream(ByteStream("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 56, 16), false);
    ASSERT_EQ(actual, expected);

    // Encoding 56 bytes RLP with as_list = true
    // NOTA: the input here is an invalid RLP element
    // NOTA: It is up to the program to build valid RLP input
    // NOTA: before inclusion in a list
    expected = ByteStream("0xF838FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                          "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 58, 16);
    actual = RLPByteStream(ByteStream("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 56, 16), true);
    ASSERT_EQ(actual, expected);

    // Encoding 65536 bytes (3 bytes-sized) RLP with as_list = false
    expected= ByteStream(Integer::zero, 65535);
    expected.push_front(0x01, 1);
    actual = RLPByteStream(expected, false);
    expected.push_front(0xBA010000, 4); //element header + 3-bytes added-prefix for the 65536 bytes element
    ASSERT_EQ(actual, expected);

    // Encoding 65536 bytes (3 bytes-sized) RLP with as_list = true
    // NOTA: the input here is an invalid RLP element
    // NOTA: It is up to the program to build valid RLP input
    // NOTA: before inclusion in a list
    expected= ByteStream(Integer::zero, 65535);
    expected.push_front(0x01, 1);
    actual = RLPByteStream(expected, true);
    expected.push_front(0xFA010000, 4); //list header + 3-bytes added-prefix for the 65536 bytes element
    ASSERT_EQ(actual, expected);
}

TEST(RLPTests, TestRLP_PushBack)
{   //Push-back empty ByteStream with at_top_level = false
    ByteStream expected(0x80);
    RLPByteStream actual;
    actual.push_back(ByteStream(), false);
    ASSERT_EQ(actual, expected);

    //Push-back empty ByteStream over empty ByteStream with at_top_level = true
    expected = ByteStream(0x80);
    actual.clear();
    actual.push_back(ByteStream(), true);
    ASSERT_EQ(actual, expected);

    //Push-back empty ByteStream over empty element with at_top_level = false
    expected = ByteStream(0xC28080);
    actual = RLPByteStream("0x80");
    actual.push_back(ByteStream(), false);
    ASSERT_EQ(actual, expected);

    //Push-back empty ByteStream over empty element with at_top_level = true
    expected = ByteStream(0xC28080);
    actual = RLPByteStream("0x80");
    actual.push_back(ByteStream(), true);
    ASSERT_EQ(actual, expected);

   //Push-back empty ByteStream over empty list with at_top_level = false
    expected = ByteStream(0xC180);
    actual = RLPByteStream("0xC0");
    actual.push_back(ByteStream(), false);
    ASSERT_EQ(actual, expected);

    //Push-back empty ByteStream over empty list with at_top_level = true
    expected = ByteStream(0xC2C080);
    actual = RLPByteStream("0xC0");
    actual.push_back(ByteStream(), true);
    ASSERT_EQ(actual, expected);

    //Push-back 56-bytes element over 55-bytes element with at_top_level = false
    expected = ByteStream( "0xF872"
                           "B7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                           "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                           "B838FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                           "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 116, 16);
    actual = RLPByteStream("0xB7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                           "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    actual.push_back(ByteStream("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 56, 16), false);
    ASSERT_EQ(actual, expected);

    //Push-back 56-bytes element over 55-bytes element with at_top_level = true
    expected = ByteStream( "0xF872"
                           "B7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                           "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                           "B838FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                           "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 116, 16);
    actual = RLPByteStream("0xB7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                           "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    actual.push_back(ByteStream("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 56, 16), true);
    ASSERT_EQ(actual, expected);

    //Push-back 56-bytes element over 55-bytes list with at_top_level = false
    // NOTA: the input here is an invalid RLP element
    // NOTA: It is up to the program to build valid RLP input
    // NOTA: before inclusion in a list
    expected = ByteStream( "0xF871"
                           "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                           "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                           "B838FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                           "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 115, 16);
    actual = RLPByteStream("0xF7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                           "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    actual.push_back(ByteStream("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 56, 16), false);
    ASSERT_EQ(actual, expected);

    //Push-back 56-bytes element over 55-bytes list with at_top_level = true
    // NOTA: the input here is an invalid RLP element
    // NOTA: It is up to the program to build valid RLP input
    // NOTA: before inclusion in a list
    expected = ByteStream( "0xF872"
                           "F7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                           "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                           "B838FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                           "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 116, 16);
    actual = RLPByteStream("0xF7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                           "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    actual.push_back(ByteStream("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 56, 16), true);
    ASSERT_EQ(actual, expected);

    //Push-back 1-byte list over 1-byte element with at_top_level = false
    expected = ByteStream( "0xC481FFC101", 5, 16);
    actual = RLPByteStream("0x81FF");
    actual.push_back(RLPByteStream(ByteStream(0x01), true), false);
    ASSERT_EQ(actual, expected);

    //Push-back 1-byte list over 1-byte element with at_top_level = true
    expected = ByteStream( "0xC481FFC101", 5, 16);
    actual = RLPByteStream("0x81FF");
    actual.push_back(RLPByteStream(ByteStream(0x01), true), true);
    ASSERT_EQ(actual, expected);

    //Push-back 1-byte list over 1-byte list with at_top_level = false
    // NOTA: the input here is an invalid RLP element
    // NOTA: It is up to the program to build valid RLP input
    // NOTA: before inclusion in a list
    expected = ByteStream( "0xC3FFC101", 4, 16);
    actual = RLPByteStream("0xC1FF");
    actual.push_back(RLPByteStream(ByteStream(0x01), true), false);
    ASSERT_EQ(actual, expected);

    //Push-back 1-byte list over 1-byte list with at_top_level = true
    // NOTA: the input here is an invalid RLP element
    // NOTA: It is up to the program to build valid RLP input
    // NOTA: before inclusion in a list
    expected = ByteStream( "0xC4C1FFC101", 5, 16);
    actual = RLPByteStream("0xC1FF");
    actual.push_back(RLPByteStream(ByteStream(0x01), true), true);
    ASSERT_EQ(actual, expected);
}

TEST(RLPTests, TestRLP_PushFront)
{   //Push_front empty ByteStream with at_top_level = false
    ByteStream expected(0x80);
    RLPByteStream actual;
    actual.push_front(ByteStream(), false);
    ASSERT_EQ(actual, expected);

    //Push_front empty ByteStream over empty ByteStream with at_top_level = true
    expected = ByteStream(0x80);
    actual.clear();
    actual.push_front(ByteStream(), true);
    ASSERT_EQ(actual, expected);

    //Push_front empty ByteStream over empty element with at_top_level = false
    expected = ByteStream(0xC28080);
    actual = RLPByteStream("0x80");
    actual.push_front(ByteStream(), false);
    ASSERT_EQ(actual, expected);

    //Push_front empty ByteStream over empty element with at_top_level = true
    expected = ByteStream(0xC28080);
    actual = RLPByteStream("0x80");
    actual.push_front(ByteStream(), true);
    ASSERT_EQ(actual, expected);

   //Push_front empty ByteStream over empty list with at_top_level = false
    expected = ByteStream(0xC180);
    actual = RLPByteStream("0xC0");
    actual.push_front(ByteStream(), false);
    ASSERT_EQ(actual, expected);

    //Push_front empty ByteStream over empty list with at_top_level = true
    expected = ByteStream(0xC280C0);
    actual = RLPByteStream("0xC0");
    actual.push_front(ByteStream(), true);
    ASSERT_EQ(actual, expected);

    //Push_front 56-bytes element over 55-bytes element with at_top_level = false
    expected = ByteStream( "0xF872"
                           "B838FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                           "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                           "B7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                           "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 116, 16);
    actual = RLPByteStream("0xB7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                           "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    actual.push_front(ByteStream("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 56, 16), false);
    ASSERT_EQ(actual, expected);

    //Push_front 56-bytes element over 55-bytes element with at_top_level = true
    expected = ByteStream( "0xF872"
                           "B838FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                           "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                           "B7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                           "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 116, 16);
    actual = RLPByteStream("0xB7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                           "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    actual.push_front(ByteStream("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 56, 16), true);
    ASSERT_EQ(actual, expected);

    //Push_front 56-bytes element over 55-bytes list with at_top_level = false
    // NOTA: the input here is an invalid RLP element
    // NOTA: It is up to the program to build valid RLP input
    // NOTA: before inclusion in a list
    expected = ByteStream( "0xF871"
                           "B838FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                           "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                           "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                           "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 115, 16);
    actual = RLPByteStream("0xF7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                           "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    actual.push_front(ByteStream("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 56, 16), false);
    ASSERT_EQ(actual, expected);

    //Push_front 56-bytes element over 55-bytes list with at_top_level = true
    // NOTA: the input here is an invalid RLP element
    // NOTA: It is up to the program to build valid RLP input
    // NOTA: before inclusion in a list
    expected = ByteStream( "0xF872"
                           "B838FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                           "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                           "F7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                           "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 116, 16);
    actual = RLPByteStream("0xF7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                           "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    actual.push_front(ByteStream("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 56, 16), true);
    ASSERT_EQ(actual, expected);

    //Push_front 1-byte list over 1-byte element with at_top_level = false
    expected = ByteStream( "0xC4C10181FF", 5, 16);
    actual = RLPByteStream("0x81FF");
    actual.push_front(RLPByteStream(ByteStream(0x01), true), false);
    ASSERT_EQ(actual, expected);

    //Push_front 1-byte list over 1-byte element with at_top_level = true
    expected = ByteStream( "0xC4C10181FF", 5, 16);
    actual = RLPByteStream("0x81FF");
    actual.push_front(RLPByteStream(ByteStream(0x01), true), true);
    ASSERT_EQ(actual, expected);

    //Push_front 1-byte list over 1-byte list with at_top_level = false
    expected = ByteStream( "0xC3C101FF", 4, 16);
    actual = RLPByteStream("0xC1FF");
    // NOTA: the input here is an invalid RLP element
    // NOTA: It is up to the program to build valid RLP input
    // NOTA: before inclusion in a list
    actual.push_front(RLPByteStream(ByteStream(0x01), true), false);
    ASSERT_EQ(actual, expected);

    //Push_front 1-byte list over 1-byte list with at_top_level = true
    // NOTA: the input here is an invalid RLP element
    // NOTA: It is up to the program to build valid RLP input
    // NOTA: before inclusion in a list
    expected = ByteStream( "0xC4C101C1FF", 5, 16);
    actual = RLPByteStream("0xC1FF");
    actual.push_front(RLPByteStream(ByteStream(0x01), true), true);
    ASSERT_EQ(actual, expected);
}

TEST(RLPTests, TestRLP_PopFront)
{   
    bool is_list;

    //Pop_front from empty ByteStream
    ByteStream expected;
    RLPByteStream rlp;
    ByteStream actual = rlp.pop_front(is_list);
    ASSERT_EQ(actual, expected);
    ASSERT_EQ(is_list, false);

    //Pop_front from empty element
    expected = ByteStream();
    rlp = RLPByteStream("0x80");
    actual = rlp.pop_front(is_list);
    ASSERT_EQ(actual, expected);
    ASSERT_EQ(is_list, false);

   //Pop_front from empty list
    expected = ByteStream();
    rlp = RLPByteStream("0xC0");
    actual = rlp.pop_front(is_list);
    ASSERT_EQ(actual, expected);
    ASSERT_EQ(is_list, false);

    //Pop_front 55-bytes element over 56-bytes element
    expected = ByteStream( "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                           "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 55, 16);
    rlp = RLPByteStream( "0xF872"
                         "B838FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                         "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                         "B7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                         "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" );
    actual = rlp.pop_front(is_list);
    ASSERT_EQ(actual, expected);
    ASSERT_EQ(is_list, false);

    //Pop_front 55-bytes element over 56-bytes list
    //NOTA: the validity of the sub-elements of the 55-bytes list is not tested
    expected = ByteStream( "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                           "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 55, 16);
    rlp = RLPByteStream( "0xF872"
                         "B838FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                         "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                         "F7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                         "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" );
    actual = rlp.pop_front(is_list);
    ASSERT_EQ(actual, expected);
    ASSERT_EQ(is_list, false);

    //Pop_front 1-byte list over 1-byte element
    expected = ByteStream("0xC101", 1, 16);
    rlp = RLPByteStream("0xC4C10181FF");
    actual = rlp.pop_front(is_list);
    ASSERT_EQ(actual, expected);
    ASSERT_EQ(is_list, true);

    //Pop_front 1-byte list over 1-byte list
    expected = ByteStream("0xC101", 1, 16);
    rlp = RLPByteStream("0xC3C101C281FF");
    actual = rlp.pop_front(is_list);
    ASSERT_EQ(actual, expected);
    ASSERT_EQ(is_list, true);

    //Test the full consumption of the list
    rlp = RLPByteStream("0xC3C10180C281FF81FFC0");
    rlp.pop_front(is_list);
    rlp.pop_front(is_list);
    rlp.pop_front(is_list);
    rlp.pop_front(is_list);
    rlp.pop_front(is_list);
    ASSERT_EQ(rlp.byteSize(), 0);
}

TEST(RLPTests, TestRLP_EIP1559WithAccessList)
{
    //From https://etherscan.io/tx/0x900aaf292c81909d9bc4d50812f30b36d44c774338b111f174b77d8a1e17e1c1

    //the transaction type (2) is omitted here: the purpose is to test the RLP part:
    RLPByteStream expected_rlp( "f9055401826eb780850e78a5df3383124f8094a57bd00134b2850b2a1c55860c"
                                "9e9ea100fdd6cf80b902041cff79cd000000000000000000000000aa2ec16d77"
                                "cfc057fb9c516282fef9da9de1e9870000000000000000000000000000000000"
                                "0000000000000000000000000000400000000000000000000000000000000000"
                                "0000000000000000000000000001844f0c7c0a00000000000000000000000000"
                                "00000000000000000000000000000000000bb8000000000000000000000000c0"
                                "2aaa39b223fe8d0a0e5c4f27ead9083c756cc2000000000000000000000000da"
                                "c17f958d2ee523a2206206994597c13d831ec700000000000000000000000056"
                                "178a0d5f301baf6cf3e1cd53d9863437345bf900000000000000000000000000"
                                "0000000000000000000000002386f26fc1000000000000000000000000000000"
                                "00000000000000000000a2a15d09519be0000000000000000000000000000000"
                                "0000000000000000cd5d9c9ffa83c88707540000000000000000000000000000"
                                "00000000000000000000002ad622051f0a400000000000000000000000000000"
                                "000000000000000003a5828e00e9d7bb9b347e00000000000000000000000000"
                                "00000000000000000000000de0b6b3a764000000000000000000000000000000"
                                "000000000000000000000000000000612782c200000000000000000000000000"
                                "0000000000000000000000000000000000003300000000000000000000000000"
                                "000000000000000000000000000000f902e2d694a56006a9bc78fd64404b34d4"
                                "4f06d1141f8589bec0d694e592427a0aece92de3edee1f18e0157c05861564c0"
                                "f8fe94dac17f958d2ee523a2206206994597c13d831ec7f8e7a0f79325ef15d7"
                                "3bc873d975b0e4eedaf108f1a270300e4b40424347eae19bc685a0af50917ef2"
                                "66a63852df327a118d37bd04d770347c3dfc528d177928d9263066a000000000"
                                "00000000000000000000000000000000000000000000000000000000a0000000"
                                "000000000000000000000000000000000000000000000000000000000aa00000"
                                "000000000000000000000000000000000000000000000000000000000004a000"
                                "00000000000000000000000000000000000000000000000000000000000003a0"
                                "447ca931bbc745ec7d2310d11914e4e40b840765b32592a566191228fbbd2ce4"
                                "d694aa2ec16d77cfc057fb9c516282fef9da9de1e987c0f8bc94c02aaa39b223"
                                "fe8d0a0e5c4f27ead9083c756cc2f8a5a00a57c8bae4ecff7c613785bbda00a6"
                                "9fbdda07ce911b9bfb285742752e6b4215a030bd84b96629f958113934633d3b"
                                "d1b64c3d259a85c57ceac65da8c5ec9bf3a7a0b0b00dbdb054c95b5c2e5f3f7f"
                                "acd24c4530e27329e985fe8efb5f6876c253f9a0217fdff7afc5cd5a4e8ef414"
                                "6b5a8c30926ffa20f0ff879ffdc9ed3476cd86eea040f963d8ab5de5259e130f"
                                "6865b75ceb44638428ca149b7fe63a511f142fedb7f8dd944e68ccd3e89f51c3"
                                "074ca5072bbac773960dfa36f8c6a0ad860a26b2adedd5a0c5d198c9503a420b"
                                "a615f9041c00093858eff051edf0a0a000000000000000000000000000000000"
                                "00000000000000000000000000000001a0000000000000000000000000000000"
                                "0000000000000000000000000000000000a00000000000000000000000000000"
                                "000000000000000000000000000000000004a000000000000000000000000000"
                                "0000000000000000000000000000000000000da0000000000000000000000000"
                                "000000000000000000000000000000000000000c01a0cba87bd34ba8ff68e25d"
                                "6b7ebd29833d64f52f2b9c2b835183b830c9dec091eba0307598bd8cb3b2c8f1"
                                "ae26f5faab724bd682a898983f9116d989e05b71836c36");

    //A copy is necessary because popping data truncates the rlp
    RLPByteStream expected_rlp_copy(expected_rlp);  

    //Test the type recognition (element/list) before casting to an element
    bool is_list;
    RLPByteStream actual_chain_id_candidate = expected_rlp_copy.pop_front(is_list);
    ASSERT_EQ(is_list, false);
    ByteStream actual_chain_id = actual_chain_id_candidate;
    
    ByteStream actual_nonce = expected_rlp_copy.pop_front(is_list);
    ByteStream actual_max_priority_fee_per_gas = expected_rlp_copy.pop_front(is_list);
    ByteStream actual_max_fee_per_gas = expected_rlp_copy.pop_front(is_list);
    ByteStream actual_gas_limit = expected_rlp_copy.pop_front(is_list);
    ByteStream actual_to = expected_rlp_copy.pop_front(is_list);
    ByteStream actual_eth = expected_rlp_copy.pop_front(is_list);
    ByteStream actual_data = expected_rlp_copy.pop_front(is_list);
    RLPByteStream actual_access_list = expected_rlp_copy.pop_front(is_list);   //RLPByteStream allows further demultiplexing
    //Test the type recognition (=list)
    ASSERT_EQ(is_list, true);
    ByteStream actual_signature_y_parity = expected_rlp_copy.pop_front(is_list);
    ByteStream actual_signature_r = expected_rlp_copy.pop_front(is_list);
    ByteStream actual_signature_s = expected_rlp_copy.pop_front(is_list);

    ByteStream expected_chain_id = ByteStream(0x01);
    ByteStream expected_nonce = ByteStream(0x6eb7);
    ByteStream expected_max_priority_fee_per_gas = ByteStream();
    ByteStream expected_max_fee_per_gas = ByteStream(0x0e78a5df33);
    ByteStream expected_gas_limit = ByteStream(0x124f80);
    ByteStream expected_to = ByteStream("a57bd00134b2850b2a1c55860c9e9ea100fdd6cf", 20, 16);
    ByteStream expected_eth = ByteStream();
    ByteStream expected_data = ByteStream( "0x1cff79cd"
                                           "000000000000000000000000aa2ec16d77cfc057fb9c516282fef9da9de1e987"
                                           "0000000000000000000000000000000000000000000000000000000000000040"
                                           "0000000000000000000000000000000000000000000000000000000000000184"
                                           "4f0c7c0a00000000000000000000000000000000000000000000000000000000"
                                           "00000bb8000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead908"
                                           "3c756cc2000000000000000000000000dac17f958d2ee523a2206206994597c1"
                                           "3d831ec700000000000000000000000056178a0d5f301baf6cf3e1cd53d98634"
                                           "37345bf9000000000000000000000000000000000000000000000000002386f2"
                                           "6fc100000000000000000000000000000000000000000000000000a2a15d0951"
                                           "9be00000000000000000000000000000000000000000000000cd5d9c9ffa83c8"
                                           "870754000000000000000000000000000000000000000000000000002ad62205"
                                           "1f0a400000000000000000000000000000000000000000000003a5828e00e9d7"
                                           "bb9b347e0000000000000000000000000000000000000000000000000de0b6b3"
                                           "a764000000000000000000000000000000000000000000000000000000000000"
                                           "612782c200000000000000000000000000000000000000000000000000000000"
                                           "0000003300000000000000000000000000000000000000000000000000000000", 516, 16 );
    RLPByteStream expected_access_list = RLPByteStream( "0xf902e2d694a56006a9bc78fd64404b34d44f06d1141f8589bec0d694e592427a"
                                                        "0aece92de3edee1f18e0157c05861564c0f8fe94dac17f958d2ee523a220620699"
                                                        "4597c13d831ec7f8e7a0f79325ef15d73bc873d975b0e4eedaf108f1a270300e4b"
                                                        "40424347eae19bc685a0af50917ef266a63852df327a118d37bd04d770347c3dfc"
                                                        "528d177928d9263066a00000000000000000000000000000000000000000000000"
                                                        "000000000000000000a00000000000000000000000000000000000000000000000"
                                                        "00000000000000000aa00000000000000000000000000000000000000000000000"
                                                        "000000000000000004a00000000000000000000000000000000000000000000000"
                                                        "000000000000000003a0447ca931bbc745ec7d2310d11914e4e40b840765b32592"
                                                        "a566191228fbbd2ce4d694aa2ec16d77cfc057fb9c516282fef9da9de1e987c0f8"
                                                        "bc94c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2f8a5a00a57c8bae4ecff7c"
                                                        "613785bbda00a69fbdda07ce911b9bfb285742752e6b4215a030bd84b96629f958"
                                                        "113934633d3bd1b64c3d259a85c57ceac65da8c5ec9bf3a7a0b0b00dbdb054c95b"
                                                        "5c2e5f3f7facd24c4530e27329e985fe8efb5f6876c253f9a0217fdff7afc5cd5a"
                                                        "4e8ef4146b5a8c30926ffa20f0ff879ffdc9ed3476cd86eea040f963d8ab5de525"
                                                        "9e130f6865b75ceb44638428ca149b7fe63a511f142fedb7f8dd944e68ccd3e89f"
                                                        "51c3074ca5072bbac773960dfa36f8c6a0ad860a26b2adedd5a0c5d198c9503a42"
                                                        "0ba615f9041c00093858eff051edf0a0a000000000000000000000000000000000"
                                                        "00000000000000000000000000000001a000000000000000000000000000000000"
                                                        "00000000000000000000000000000000a000000000000000000000000000000000"
                                                        "00000000000000000000000000000004a000000000000000000000000000000000"
                                                        "0000000000000000000000000000000da000000000000000000000000000000000"
                                                        "0000000000000000000000000000000c" );
    ByteStream expected_signature_y_parity = ByteStream(0x01);
    ByteStream expected_signature_r = ByteStream("0xcba87bd34ba8ff68e25d6b7ebd29833d64f52f2b9c2b835183b830c9dec091eb", 32, 16);
    ByteStream expected_signature_s = ByteStream("0x307598bd8cb3b2c8f1ae26f5faab724bd682a898983f9116d989e05b71836c36", 32, 16);

    ASSERT_EQ(actual_chain_id, expected_chain_id);
    ASSERT_EQ(actual_nonce, expected_nonce);
    ASSERT_EQ(actual_max_priority_fee_per_gas, expected_max_priority_fee_per_gas);
    ASSERT_EQ(actual_max_fee_per_gas, expected_max_fee_per_gas);
    ASSERT_EQ(actual_gas_limit, expected_gas_limit);
    ASSERT_EQ(actual_to, expected_to);
    ASSERT_EQ(actual_eth, expected_eth);
    ASSERT_EQ(actual_data, expected_data);
    ASSERT_EQ(actual_access_list, expected_access_list);
    ASSERT_EQ(actual_signature_y_parity, expected_signature_y_parity);
    ASSERT_EQ(actual_signature_r, expected_signature_r);
    ASSERT_EQ(actual_signature_s, expected_signature_s);

    //Test the conformity of the access_list sub-lists
    RLPByteStream actual_access_list1 = actual_access_list.pop_front(is_list);
    RLPByteStream actual_access_list2 = actual_access_list.pop_front(is_list);
    RLPByteStream actual_access_list3 = actual_access_list.pop_front(is_list);
    RLPByteStream actual_access_list4 = actual_access_list.pop_front(is_list);
    RLPByteStream actual_access_list5 = actual_access_list.pop_front(is_list);
    RLPByteStream actual_access_list6 = actual_access_list.pop_front(is_list);
    RLPByteStream expected_access_list1 = RLPByteStream( "d694a56006a9bc78fd64404b34d44f06d1141f8589bec0" );
    RLPByteStream expected_access_list2 = RLPByteStream( "d694e592427a0aece92de3edee1f18e0157c05861564c0" );
    RLPByteStream expected_access_list3 = RLPByteStream( "f8fe94dac17f958d2ee523a220620699"
                                                         "4597c13d831ec7f8e7a0f79325ef15d73bc873d975b0e4eedaf108f1a270300e4b"
                                                         "40424347eae19bc685a0af50917ef266a63852df327a118d37bd04d770347c3dfc"
                                                         "528d177928d9263066a00000000000000000000000000000000000000000000000"
                                                         "000000000000000000a00000000000000000000000000000000000000000000000"
                                                         "00000000000000000aa00000000000000000000000000000000000000000000000"
                                                         "000000000000000004a00000000000000000000000000000000000000000000000"
                                                         "000000000000000003a0447ca931bbc745ec7d2310d11914e4e40b840765b32592"
                                                         "a566191228fbbd2ce4" );
    RLPByteStream expected_access_list4 = RLPByteStream( "d694aa2ec16d77cfc057fb9c516282fef9da9de1e987c0");
    RLPByteStream expected_access_list5 = RLPByteStream( "f8"
                                                         "bc94c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2f8a5a00a57c8bae4ecff7c"
                                                         "613785bbda00a69fbdda07ce911b9bfb285742752e6b4215a030bd84b96629f958"
                                                         "113934633d3bd1b64c3d259a85c57ceac65da8c5ec9bf3a7a0b0b00dbdb054c95b"
                                                         "5c2e5f3f7facd24c4530e27329e985fe8efb5f6876c253f9a0217fdff7afc5cd5a"
                                                         "4e8ef4146b5a8c30926ffa20f0ff879ffdc9ed3476cd86eea040f963d8ab5de525"
                                                         "9e130f6865b75ceb44638428ca149b7fe63a511f142fedb7");
    RLPByteStream expected_access_list6 = RLPByteStream( "f8dd944e68ccd3e89f"
                                                         "51c3074ca5072bbac773960dfa36f8c6a0ad860a26b2adedd5a0c5d198c9503a42"
                                                         "0ba615f9041c00093858eff051edf0a0a000000000000000000000000000000000"
                                                         "00000000000000000000000000000001a000000000000000000000000000000000"
                                                         "00000000000000000000000000000000a000000000000000000000000000000000"
                                                         "00000000000000000000000000000004a000000000000000000000000000000000"
                                                         "0000000000000000000000000000000da000000000000000000000000000000000"
                                                         "0000000000000000000000000000000c" );
    ASSERT_EQ(actual_access_list1, expected_access_list1);
    ASSERT_EQ(actual_access_list2, expected_access_list2);
    ASSERT_EQ(actual_access_list3, expected_access_list3);
    ASSERT_EQ(actual_access_list4, expected_access_list4);
    ASSERT_EQ(actual_access_list5, expected_access_list5);
    ASSERT_EQ(actual_access_list6, expected_access_list6);
    ASSERT_EQ(actual_access_list.byteSize(), 0);

    //Deserializes until reaching address/keystores for list5
    ByteStream actual_access_list5_address = actual_access_list5.pop_front(is_list);
    RLPByteStream actual_access_list5_keystore_list = actual_access_list5.pop_front(is_list);  //RLPByteStream allows further demultiplexing
    ByteStream actual_access_list5_keystore1 = actual_access_list5_keystore_list.pop_front(is_list);
    ByteStream actual_access_list5_keystore2 = actual_access_list5_keystore_list.pop_front(is_list);
    ByteStream actual_access_list5_keystore3 = actual_access_list5_keystore_list.pop_front(is_list);
    ByteStream actual_access_list5_keystore4 = actual_access_list5_keystore_list.pop_front(is_list);
    ByteStream actual_access_list5_keystore5 = actual_access_list5_keystore_list.pop_front(is_list);

    ByteStream expected_access_list5_address = ByteStream("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", 20, 16);
    ByteStream expected_access_list5_keystore1 = ByteStream("0x0a57c8bae4ecff7c613785bbda00a69fbdda07ce911b9bfb285742752e6b4215", 32, 16);
    ByteStream expected_access_list5_keystore2 = ByteStream("0x30bd84b96629f958113934633d3bd1b64c3d259a85c57ceac65da8c5ec9bf3a7", 32, 16);
    ByteStream expected_access_list5_keystore3 = ByteStream("0xb0b00dbdb054c95b5c2e5f3f7facd24c4530e27329e985fe8efb5f6876c253f9", 32, 16);
    ByteStream expected_access_list5_keystore4 = ByteStream("0x217fdff7afc5cd5a4e8ef4146b5a8c30926ffa20f0ff879ffdc9ed3476cd86ee", 32, 16);
    ByteStream expected_access_list5_keystore5 = ByteStream("0x40f963d8ab5de5259e130f6865b75ceb44638428ca149b7fe63a511f142fedb7", 32, 16);

    ASSERT_EQ(actual_access_list5_address, expected_access_list5_address);
    ASSERT_EQ(actual_access_list5_keystore1, expected_access_list5_keystore1);
    ASSERT_EQ(actual_access_list5_keystore2, expected_access_list5_keystore2);
    ASSERT_EQ(actual_access_list5_keystore3, expected_access_list5_keystore3);
    ASSERT_EQ(actual_access_list5_keystore4, expected_access_list5_keystore4);
    ASSERT_EQ(actual_access_list5_keystore5, expected_access_list5_keystore5);
    ASSERT_EQ(actual_access_list5.byteSize(), 0);

    //Rebuilding the transaction from scratch:
    RLPByteStream actual_rlp;
    actual_rlp.push_back(ByteStream(0x01));
    actual_rlp.push_back(ByteStream(0x6eb7));
    actual_rlp.push_back(ByteStream());
    actual_rlp.push_back(ByteStream(0x0e78a5df33));
    actual_rlp.push_back(ByteStream(0x124f80));
    actual_rlp.push_back(ByteStream("a57bd00134b2850b2a1c55860c9e9ea100fdd6cf", 20, 16));
    actual_rlp.push_back(ByteStream());
    actual_rlp.push_back(ByteStream("0x1cff79cd"
                                           "000000000000000000000000aa2ec16d77cfc057fb9c516282fef9da9de1e987"
                                           "0000000000000000000000000000000000000000000000000000000000000040"
                                           "0000000000000000000000000000000000000000000000000000000000000184"
                                           "4f0c7c0a00000000000000000000000000000000000000000000000000000000"
                                           "00000bb8000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead908"
                                           "3c756cc2000000000000000000000000dac17f958d2ee523a2206206994597c1"
                                           "3d831ec700000000000000000000000056178a0d5f301baf6cf3e1cd53d98634"
                                           "37345bf9000000000000000000000000000000000000000000000000002386f2"
                                           "6fc100000000000000000000000000000000000000000000000000a2a15d0951"
                                           "9be00000000000000000000000000000000000000000000000cd5d9c9ffa83c8"
                                           "870754000000000000000000000000000000000000000000000000002ad62205"
                                           "1f0a400000000000000000000000000000000000000000000003a5828e00e9d7"
                                           "bb9b347e0000000000000000000000000000000000000000000000000de0b6b3"
                                           "a764000000000000000000000000000000000000000000000000000000000000"
                                           "612782c200000000000000000000000000000000000000000000000000000000"
                                           "0000003300000000000000000000000000000000000000000000000000000000", 516, 16 ));

    actual_access_list1 = ByteStream("0xa56006a9bc78fd64404b34d44f06d1141f8589be", 20, 16);
    actual_access_list1.push_back(RLPByteStream(ByteStream(), true));

    actual_access_list2 = ByteStream("0xe592427a0aece92de3edee1f18e0157c05861564", 20, 16);
    actual_access_list2.push_back(RLPByteStream(ByteStream(), true));

    actual_access_list3 = ByteStream("0xf79325ef15d73bc873d975b0e4eedaf108f1a270300e4b40424347eae19bc685", 32, 16);
    actual_access_list3.push_back(ByteStream("0xaf50917ef266a63852df327a118d37bd04d770347c3dfc528d177928d9263066", 32, 16));
    actual_access_list3.push_back(ByteStream("0x0000000000000000000000000000000000000000000000000000000000000000", 32, 16));
    actual_access_list3.push_back(ByteStream("0x000000000000000000000000000000000000000000000000000000000000000a", 32, 16));
    actual_access_list3.push_back(ByteStream("0x0000000000000000000000000000000000000000000000000000000000000004", 32, 16));
    actual_access_list3.push_back(ByteStream("0x0000000000000000000000000000000000000000000000000000000000000003", 32, 16));
    actual_access_list3.push_back(ByteStream("0x447ca931bbc745ec7d2310d11914e4e40b840765b32592a566191228fbbd2ce4", 32, 16));
    actual_access_list3.push_front(ByteStream("0xdac17f958d2ee523a2206206994597c13d831ec7", 20, 16), true);

    actual_access_list4 = ByteStream("0xaa2ec16d77cfc057fb9c516282fef9da9de1e987", 20, 16);
    actual_access_list4.push_back(RLPByteStream(ByteStream(), true));

    actual_access_list5 = ByteStream("0x0a57c8bae4ecff7c613785bbda00a69fbdda07ce911b9bfb285742752e6b4215", 32, 16);
    actual_access_list5.push_back(ByteStream("0x30bd84b96629f958113934633d3bd1b64c3d259a85c57ceac65da8c5ec9bf3a7", 32, 16));
    actual_access_list5.push_back(ByteStream("0xb0b00dbdb054c95b5c2e5f3f7facd24c4530e27329e985fe8efb5f6876c253f9", 32, 16));
    actual_access_list5.push_back(ByteStream("0x217fdff7afc5cd5a4e8ef4146b5a8c30926ffa20f0ff879ffdc9ed3476cd86ee", 32, 16));
    actual_access_list5.push_back(ByteStream("0x40f963d8ab5de5259e130f6865b75ceb44638428ca149b7fe63a511f142fedb7", 32, 16));
    actual_access_list5.push_front(ByteStream("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", 20, 16), true);

    actual_access_list6 = ByteStream("0xad860a26b2adedd5a0c5d198c9503a420ba615f9041c00093858eff051edf0a0", 32, 16);
    actual_access_list6.push_back(ByteStream("0x0000000000000000000000000000000000000000000000000000000000000001", 32, 16));
    actual_access_list6.push_back(ByteStream("0x0000000000000000000000000000000000000000000000000000000000000000", 32, 16));
    actual_access_list6.push_back(ByteStream("0x0000000000000000000000000000000000000000000000000000000000000004", 32, 16));
    actual_access_list6.push_back(ByteStream("0x000000000000000000000000000000000000000000000000000000000000000d", 32, 16));
    actual_access_list6.push_back(ByteStream("0x000000000000000000000000000000000000000000000000000000000000000c", 32, 16));
    actual_access_list6.push_front(ByteStream("0x4e68ccd3e89f51c3074ca5072bbac773960dfa36", 20, 16), true);

    actual_access_list.clear();
    actual_access_list.push_front(actual_access_list3);
    actual_access_list.push_back(actual_access_list4, true);    //the second list is next to the first one, thus creating a new top_list
    actual_access_list.push_front(actual_access_list2);
    actual_access_list.push_back(actual_access_list5);
    actual_access_list.push_front(actual_access_list1);
    actual_access_list.push_back(actual_access_list6);

    actual_rlp.push_back(actual_access_list);
    actual_rlp.push_back(ByteStream(0x01));
    actual_rlp.push_back(ByteStream("0xcba87bd34ba8ff68e25d6b7ebd29833d64f52f2b9c2b835183b830c9dec091eb", 32, 16));
    actual_rlp.push_back(ByteStream("0x307598bd8cb3b2c8f1ae26f5faab724bd682a898983f9116d989e05b71836c36", 32, 16));

    ASSERT_EQ(actual_rlp, expected_rlp);
}
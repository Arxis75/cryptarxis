#include <gtest/gtest.h>
#include <crypto/bips.h>

using namespace std;
using namespace BIP39;

string TestMnemonic_set_n_test_words(BIP39::Mnemonic& mnc, uint8_t n)
{   
    string expected;
    uint16_t cs = mnc.getEntropySize() / 32;
    uint16_t ms = (mnc.getEntropySize() + cs) / 11;
    mnc.clear();
    for(int i=0;i<min(int(n), ms-1);i++)
    {
        mnc.add_word("abandon");
        expected += "abandon ";
    }
    if(ms == 12 && n == 12)
    {
        mnc.add_word("wrap");
        expected += "wrap";
    }
    else if(ms == 15 && n == 15)
    {
        mnc.add_word("word");
        expected += "word";
    }
    else if(ms == 18 && n == 18)
    {
        mnc.add_word("wedding");
        expected += "wedding";
    }
    else if(ms == 21 && n == 21)
    {
        mnc.add_word("verify");
        expected += "verify";
    }
    else if(ms == 24 && n == 24)
    {
        mnc.add_word("trouble");
        expected += "trouble";
    }
    if( !strcmp(&(*expected.rbegin()), " ") )
        expected.erase(expected.size()-1, 1);
    return expected;
}

TEST(MnemonicTests, TestMnemonic_init)
{
    Mnemonic mnc(256);
    auto expected = "";
    auto actual = mnc.get_word_list();
    ASSERT_EQ(actual, expected);
}

TEST(MnemonicTests, TestMnemonic_add_word)
{
    Mnemonic mnc(256);
    
    //---- adds invalid word ----
    mnc.add_word("abandonn");
    string expected = "";
    auto actual = mnc.get_word_list();
    ASSERT_EQ(actual, expected);
    
    //---- adds mixed uppercase/lowercase word ----
    mnc.add_word("AbAnDoN");
    expected = "abandon";
    actual = mnc.get_word_list();
    ASSERT_EQ(actual, expected);
    
    //---- 23 x adds 1 word ----
    expected = TestMnemonic_set_n_test_words(mnc, 23);
    actual = mnc.get_word_list();
    ASSERT_EQ(actual, expected);

    //---- adds invalid 24th words ----
    mnc.add_word("abandon");
    actual = mnc.get_word_list();
    ASSERT_EQ(actual, expected);

    //---- adds invalid 24th words ----
    mnc.add_word("puzzle");
    actual = mnc.get_word_list();
    ASSERT_EQ(actual, expected);

    //---- adds invalid 24th words ----
    mnc.add_word("zoo");
    actual = mnc.get_word_list();
    ASSERT_EQ(actual, expected);
    
    //---- adds valid 24th word ----
    mnc.add_word("art");
    expected += " art";
    actual = mnc.get_word_list();
    ASSERT_EQ(actual, expected);

    //---- adds valid 24th word ----
    expected = TestMnemonic_set_n_test_words(mnc, 23);
    mnc.add_word("diesel");
    expected += " diesel";
    actual = mnc.get_word_list();
    ASSERT_EQ(actual, expected);

    //---- adds valid 24th word ----
    expected = TestMnemonic_set_n_test_words(mnc, 23);
    mnc.add_word("false");
    expected += " false";
    actual = mnc.get_word_list();
    ASSERT_EQ(actual, expected);

    //---- adds valid 24th word ----
    expected = TestMnemonic_set_n_test_words(mnc, 23);
    mnc.add_word("kite");
    expected += " kite";
    actual = mnc.get_word_list();
    ASSERT_EQ(actual, expected);

    //---- adds valid 24th word ----
    expected = TestMnemonic_set_n_test_words(mnc, 23);
    mnc.add_word("organ");
    expected += " organ";
    actual = mnc.get_word_list();
    ASSERT_EQ(actual, expected);

    //---- adds valid 24th word ----
    expected = TestMnemonic_set_n_test_words(mnc, 23);
    mnc.add_word("ready");
    expected += " ready";
    actual = mnc.get_word_list();
    ASSERT_EQ(actual, expected);

    //---- adds valid 24th word ----
    expected = TestMnemonic_set_n_test_words(mnc, 23);
    mnc.add_word("surface");
    expected += " surface";
    actual = mnc.get_word_list();
    ASSERT_EQ(actual, expected);

    //---- adds valid 24th word ----
    expected = TestMnemonic_set_n_test_words(mnc, 23);
    mnc.add_word("trouble");
    expected += " trouble";
    actual = mnc.get_word_list();
    ASSERT_EQ(actual, expected);
}

TEST(MnemonicTests, TestMnemonic_clear)
{
    Mnemonic mnc(128);
    TestMnemonic_set_n_test_words(mnc, 12);
    
    //--- clears word list ----
    mnc.clear();
    auto expected = "";
    auto actual = mnc.get_word_list();
    ASSERT_EQ(actual, expected);
}

TEST(MnemonicTests, TestMnemonic_set_full_word_list)
{
    Mnemonic mnc(160);
    
    //--- set invalid word list ----
    mnc.set_full_word_list("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo");
    auto expected = "";
    auto actual = mnc.get_word_list();
    ASSERT_EQ(actual, expected);

    //--- set valid word list ----
    mnc.set_full_word_list("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo puzzle");
    expected = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo puzzle";
    actual = mnc.get_word_list();
    ASSERT_EQ(actual, expected);
}

TEST(MnemonicTests, TestMnemonic_is_valid)
{
    //--- 0 words is invalid ----
    Mnemonic mnc(192);
    auto expected = false;
    auto actual = mnc.is_valid();
    ASSERT_EQ(actual, expected);

    //--- 1 word is invalid ----
    mnc.add_word("abandon");
    expected = false;
    actual = mnc.is_valid();
    ASSERT_EQ(actual, expected);

    //--- 17 words is invalid ----
    TestMnemonic_set_n_test_words(mnc, 17);
    expected = false;
    actual = mnc.is_valid();
    ASSERT_EQ(actual, expected);

    //--- 18 words is valid ----
    mnc.add_word("lemon");
    expected = true;
    actual = mnc.is_valid();
    ASSERT_EQ(actual, expected);
}

TEST(MnemonicTests, TestMnemonic_list_possible_last_word)
{
    vector<string> list;
    
    //--- too much room to calculate last possible words ---
    Mnemonic mnc(224);
    auto expected = false;
    auto actual = mnc.list_possible_last_word(list);
    ASSERT_EQ(actual, expected);
    ASSERT_EQ(list.size(), 0);

    //--- no more room remaining to calculate last possible words ---
    mnc.set_full_word_list("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon verify");
    expected = false;
    actual = mnc.list_possible_last_word(list);
    ASSERT_EQ(actual, expected);
    ASSERT_EQ(list.size(), 0);
    
    //--- just enough remaining entropy room to calculate last possible words ---
    TestMnemonic_set_n_test_words(mnc, 20);
    expected = true;
    actual = mnc.list_possible_last_word(list);
    ASSERT_EQ(actual, expected);
    ASSERT_EQ(list.size(), 16);
    ASSERT_EQ(list[0], "admit");
    ASSERT_EQ(list[1], "breeze");
    ASSERT_EQ(list[2], "choose");
    ASSERT_EQ(list[3], "depart");
    ASSERT_EQ(list[4], "elegant");
    ASSERT_EQ(list[5], "fury");
    ASSERT_EQ(list[6], "hundred");
    ASSERT_EQ(list[7], "infant");
    ASSERT_EQ(list[8], "link");
    ASSERT_EQ(list[9], "mother");
    ASSERT_EQ(list[10], "plastic");
    ASSERT_EQ(list[11], "radar");
    ASSERT_EQ(list[12], "slab");
    ASSERT_EQ(list[13], "sure");
    ASSERT_EQ(list[14], "truck");
    ASSERT_EQ(list[15], "verify");
}

TEST(MnemonicTests, TestMnemonic_get_word_list)
{  
    //--- EMPTY word list ---
    Mnemonic mnc(256);
    string expected = "";
    auto actual = mnc.get_word_list();
    ASSERT_EQ(actual, expected);

    //--- N-1 word list ---
    expected = TestMnemonic_set_n_test_words(mnc, 23);
    actual = mnc.get_word_list();
    ASSERT_EQ(actual, expected);

    //--- COMPLETE word list ---
    expected = TestMnemonic_set_n_test_words(mnc, 24);
    actual = mnc.get_word_list();
    ASSERT_EQ(actual, expected);
}

TEST(MnemonicTests, TestMnemonic_get_last_word)
{
    Mnemonic mnc(256);
    auto expected = "";
    auto actual = mnc.get_last_word();
    ASSERT_EQ(actual, expected);

    TestMnemonic_set_n_test_words(mnc, 23);
    expected = "";
    actual = mnc.get_last_word();
    ASSERT_EQ(actual, expected);

    mnc.set_full_word_list("diamond recycle math quantum earn save nut spice hen rice soft wire artefact say twin drum rival live mask lens actress peasant abstract hint");
    expected = "hint";
    actual = mnc.get_last_word();
    ASSERT_EQ(actual, expected);
}
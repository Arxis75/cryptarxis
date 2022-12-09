#include <gtest/gtest.h>
#include <crypto/bips.h>

using namespace BIP39;

TEST(BIP39Tests, TestMnemonic_init)
{
    Mnemonic* mnc = new Mnemonic(256);
    auto expected = "";
    auto actual = mnc->get_word_list();
    ASSERT_EQ(actual, expected);
}

void TestMnemonic_set_23_test_words(BIP39::Mnemonic* mnc)
{
    mnc->clear();
    mnc->add_word("diamond");
    mnc->add_word("recycle");
    mnc->add_word("math");
    mnc->add_word("quantum");
    mnc->add_word("earn");
    mnc->add_word("save");
    mnc->add_word("nut");
    mnc->add_word("spice");
    mnc->add_word("hen");
    mnc->add_word("rice");
    mnc->add_word("soft");
    mnc->add_word("wire");
    mnc->add_word("artefact");
    mnc->add_word("say");
    mnc->add_word("twin");
    mnc->add_word("drum");
    mnc->add_word("rival");
    mnc->add_word("live");
    mnc->add_word("mask");
    mnc->add_word("lens");
    mnc->add_word("actress");
    mnc->add_word("peasant");
    mnc->add_word("abstract");
}

TEST(BIP39Tests, TestMnemonic_add_word)
{
    Mnemonic* mnc = new Mnemonic(256);
    
    mnc->add_word("diamondd");
    auto expected = "";
    auto actual = mnc->get_word_list();
    ASSERT_EQ(actual, expected);
    
    mnc->add_word("DiAmOnD");
    expected = "diamond";
    actual = mnc->get_word_list();
    ASSERT_EQ(actual, expected);

    mnc->add_word("recycle");
    mnc->add_word("math");
    mnc->add_word("quantum");
    mnc->add_word("earn");
    mnc->add_word("save");
    mnc->add_word("nut");
    mnc->add_word("spice");
    mnc->add_word("hen");
    mnc->add_word("rice");
    mnc->add_word("soft");
    mnc->add_word("wire");
    mnc->add_word("artefact");
    mnc->add_word("say");
    mnc->add_word("twin");
    mnc->add_word("drum");
    mnc->add_word("rival");
    mnc->add_word("live");
    mnc->add_word("mask");
    mnc->add_word("lens");
    mnc->add_word("actress");
    mnc->add_word("peasant");
    mnc->add_word("abstract");
    expected = "diamond recycle math quantum earn save nut spice hen rice soft wire artefact say twin drum rival live mask lens actress peasant abstract";
    actual = mnc->get_word_list();
    ASSERT_EQ(actual, expected);

    mnc->add_word("zoo");
    expected = "diamond recycle math quantum earn save nut spice hen rice soft wire artefact say twin drum rival live mask lens actress peasant abstract";
    actual = mnc->get_word_list();
    ASSERT_EQ(actual, expected);

    mnc->add_word("hint");
    expected = "diamond recycle math quantum earn save nut spice hen rice soft wire artefact say twin drum rival live mask lens actress peasant abstract hint";
    actual = mnc->get_word_list();
    ASSERT_EQ(actual, expected);

    TestMnemonic_set_23_test_words(mnc);
    mnc->add_word("balance");
    expected = "diamond recycle math quantum earn save nut spice hen rice soft wire artefact say twin drum rival live mask lens actress peasant abstract balance";
    actual = mnc->get_word_list();
    ASSERT_EQ(actual, expected);

    TestMnemonic_set_23_test_words(mnc);
    mnc->add_word("coin");
    expected = "diamond recycle math quantum earn save nut spice hen rice soft wire artefact say twin drum rival live mask lens actress peasant abstract coin";
    actual = mnc->get_word_list();
    ASSERT_EQ(actual, expected);

    TestMnemonic_set_23_test_words(mnc);
    mnc->add_word("foam");
    expected = "diamond recycle math quantum earn save nut spice hen rice soft wire artefact say twin drum rival live mask lens actress peasant abstract foam";
    actual = mnc->get_word_list();
    ASSERT_EQ(actual, expected);

    TestMnemonic_set_23_test_words(mnc);
    mnc->add_word("hint");
    expected = "diamond recycle math quantum earn save nut spice hen rice soft wire artefact say twin drum rival live mask lens actress peasant abstract hint";
    actual = mnc->get_word_list();
    ASSERT_EQ(actual, expected);

    TestMnemonic_set_23_test_words(mnc);
    mnc->add_word("opera");
    expected = "diamond recycle math quantum earn save nut spice hen rice soft wire artefact say twin drum rival live mask lens actress peasant abstract opera";
    actual = mnc->get_word_list();
    ASSERT_EQ(actual, expected);

    TestMnemonic_set_23_test_words(mnc);
    mnc->add_word("runway");
    expected = "diamond recycle math quantum earn save nut spice hen rice soft wire artefact say twin drum rival live mask lens actress peasant abstract runway";
    actual = mnc->get_word_list();
    ASSERT_EQ(actual, expected);

    TestMnemonic_set_23_test_words(mnc);
    mnc->add_word("swarm");
    expected = "diamond recycle math quantum earn save nut spice hen rice soft wire artefact say twin drum rival live mask lens actress peasant abstract swarm";
    actual = mnc->get_word_list();
    ASSERT_EQ(actual, expected);

    TestMnemonic_set_23_test_words(mnc);
    mnc->add_word("trophy");
    expected = "diamond recycle math quantum earn save nut spice hen rice soft wire artefact say twin drum rival live mask lens actress peasant abstract trophy";
    actual = mnc->get_word_list();
    ASSERT_EQ(actual, expected);
}

TEST(BIP39Tests, TestMnemonic_clear)
{
    Mnemonic* mnc = new Mnemonic(256);
    mnc->set_full_word_list("diamond recycle math quantum earn save nut spice hen rice soft wire artefact say twin drum rival live mask lens actress peasant abstract hint");
    
    mnc->clear();
    auto expected = "";
    auto actual = mnc->get_word_list();
    ASSERT_EQ(actual, expected);
}

TEST(BIP39Tests, TestMnemonic_set_full_word_list)
{
    Mnemonic* mnc = new Mnemonic(256);
    
    mnc->set_full_word_list("diamond         math quantum earn save nut spice hen rice soft wire artefact say twin drum rival live mask lens actress peasant abstract hint");
    auto expected = "";
    auto actual = mnc->get_word_list();
    ASSERT_EQ(actual, expected);

    mnc->set_full_word_list("diamond recycle math quantum earn save nut spice hen rice soft wire artefact say twin drum rival live mask lens actress peasant abstract hint");
    expected = "diamond recycle math quantum earn save nut spice hen rice soft wire artefact say twin drum rival live mask lens actress peasant abstract hint";
    actual = mnc->get_word_list();
    ASSERT_EQ(actual, expected);
}

TEST(BIP39Tests, TestMnemonic_is_valid)
{
    Mnemonic* mnc = new Mnemonic(256);
    auto expected = false;
    auto actual = mnc->is_valid();
    ASSERT_EQ(actual, expected);

    mnc->add_word("diamond");
    expected = false;
    actual = mnc->is_valid();
    ASSERT_EQ(actual, expected);

    TestMnemonic_set_23_test_words(mnc);
    expected = false;
    actual = mnc->is_valid();
    ASSERT_EQ(actual, expected);

    mnc->add_word("hint");
    expected = true;
    actual = mnc->is_valid();
    ASSERT_EQ(actual, expected);
}

TEST(BIP39Tests, TestMnemonic_list_possible_last_word)
{
    vector<string> list;
    
    Mnemonic* mnc = new Mnemonic(256);
    auto expected = false;
    auto actual = mnc->list_possible_last_word(list);
    ASSERT_EQ(actual, expected);
    ASSERT_EQ(list.size(), 0);

    mnc->set_full_word_list("diamond recycle math quantum earn save nut spice hen rice soft wire artefact say twin drum rival live mask lens actress peasant abstract hint");
    expected = false;
    actual = mnc->list_possible_last_word(list);
    ASSERT_EQ(actual, expected);
    ASSERT_EQ(list.size(), 0);

    TestMnemonic_set_23_test_words(mnc);
    expected = true;
    actual = mnc->list_possible_last_word(list);
    ASSERT_EQ(actual, expected);
    ASSERT_EQ(list.size(), 8);
    ASSERT_EQ(list[0], "balance");
    ASSERT_EQ(list[1], "coin");
    ASSERT_EQ(list[2], "foam");
    ASSERT_EQ(list[3], "hint");
    ASSERT_EQ(list[4], "opera");
    ASSERT_EQ(list[5], "runway");
    ASSERT_EQ(list[6], "swarm");
    ASSERT_EQ(list[7], "trophy");
}

TEST(BIP39Tests, TestMnemonic_get_word_list)
{  
    Mnemonic* mnc = new Mnemonic(256);
    auto expected = "";
    auto actual = mnc->get_word_list();
    ASSERT_EQ(actual, expected);

    TestMnemonic_set_23_test_words(mnc);
    expected = "diamond recycle math quantum earn save nut spice hen rice soft wire artefact say twin drum rival live mask lens actress peasant abstract";
    actual = mnc->get_word_list();
    ASSERT_EQ(actual, expected);

    mnc->set_full_word_list("diamond recycle math quantum earn save nut spice hen rice soft wire artefact say twin drum rival live mask lens actress peasant abstract hint");
    expected = "diamond recycle math quantum earn save nut spice hen rice soft wire artefact say twin drum rival live mask lens actress peasant abstract hint";
    actual = mnc->get_word_list();
    ASSERT_EQ(actual, expected);
}

TEST(BIP39Tests, TestMnemonic_get_last_word)
{
    Mnemonic* mnc = new Mnemonic(256);
    auto expected = "";
    auto actual = mnc->get_last_word();
    ASSERT_EQ(actual, expected);

    TestMnemonic_set_23_test_words(mnc);
    expected = "";
    actual = mnc->get_last_word();
    ASSERT_EQ(actual, expected);

    mnc->set_full_word_list("diamond recycle math quantum earn save nut spice hen rice soft wire artefact say twin drum rival live mask lens actress peasant abstract hint");
    expected = "hint";
    actual = mnc->get_last_word();
    ASSERT_EQ(actual, expected);
}

TEST(BIP39Tests, TestMnemonic_get_seed)
{
    auto expected = 0;
    auto actual = 0;
    ASSERT_EQ(actual, expected);
}
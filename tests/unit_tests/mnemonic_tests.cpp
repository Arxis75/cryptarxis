#include <gtest/gtest.h>
#include <crypto/bips.h>

using namespace std;
using namespace BIP39;

TEST(BIP39Tests, TestMnemonic_init)
{
    Mnemonic mnc(256);
    auto expected = "";
    auto actual = mnc.get_word_list();
    ASSERT_EQ(actual, expected);
}

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

TEST(BIP39Tests, TestMnemonic_add_word)
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

TEST(BIP39Tests, TestMnemonic_clear)
{
    Mnemonic mnc(128);
    TestMnemonic_set_n_test_words(mnc, 12);
    
    //--- clears word list ----
    mnc.clear();
    auto expected = "";
    auto actual = mnc.get_word_list();
    ASSERT_EQ(actual, expected);
}

TEST(BIP39Tests, TestMnemonic_set_full_word_list)
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

TEST(BIP39Tests, TestMnemonic_is_valid)
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

TEST(BIP39Tests, TestMnemonic_list_possible_last_word)
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

TEST(BIP39Tests, TestMnemonic_get_word_list)
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

TEST(BIP39Tests, TestMnemonic_get_last_word)
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

TEST(BIP39Tests, TestMnemonic_get_seed)
{
    Mnemonic mnc = Mnemonic(128);
    mnc.add_entropy("00000000000000000000000000000000", 128, 16);
    auto expected = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    auto actual = mnc.get_word_list();
    ASSERT_EQ(actual, expected);
    Bitstream expected_seed = Bitstream("c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04", 512, 16);
    Bitstream actual_seed = mnc.get_seed("TREZOR");
    ASSERT_EQ(actual_seed, expected_seed);

    mnc = Mnemonic(128);
    mnc.add_entropy("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", 128, 16);
    expected = "legal winner thank year wave sausage worth useful legal winner thank yellow";
    actual = mnc.get_word_list();
    ASSERT_EQ(actual, expected);
    expected_seed = Bitstream("2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607", 512, 16);
    actual_seed = mnc.get_seed("TREZOR");
    ASSERT_EQ(actual_seed, expected_seed);

    mnc = Mnemonic(128);
    mnc.add_entropy("80808080808080808080808080808080", 128, 16);
    expected = "letter advice cage absurd amount doctor acoustic avoid letter advice cage above";
    actual = mnc.get_word_list();
    ASSERT_EQ(actual, expected);
    expected_seed = Bitstream("d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8", 512, 16);
    actual_seed = mnc.get_seed("TREZOR");
    ASSERT_EQ(actual_seed, expected_seed);

    mnc = Mnemonic(128);
    mnc.add_entropy("ffffffffffffffffffffffffffffffff", 128, 16);
    expected = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";
    actual = mnc.get_word_list();
    ASSERT_EQ(actual, expected);
    expected_seed = Bitstream("ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069", 512, 16);
    actual_seed = mnc.get_seed("TREZOR");
    ASSERT_EQ(actual_seed, expected_seed);

    mnc = Mnemonic(192);
    mnc.add_entropy("000000000000000000000000000000000000000000000000", 192, 16);
    expected = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent";
    actual = mnc.get_word_list();
    ASSERT_EQ(actual, expected);
    expected_seed = Bitstream("035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa", 512, 16);
    actual_seed = mnc.get_seed("TREZOR");
    ASSERT_EQ(actual_seed, expected_seed);

    mnc = Mnemonic(192);
    mnc.add_entropy("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", 192, 16);
    expected = "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will";
    actual = mnc.get_word_list();
    ASSERT_EQ(actual, expected);
    expected_seed = Bitstream("f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a0c7b3c392d168748f2d4a612bada0753b52a1c7ac53c1e93abd5c6320b9e95dd", 512, 16);
    actual_seed = mnc.get_seed("TREZOR");
    ASSERT_EQ(actual_seed, expected_seed);

    mnc = Mnemonic(192);
    mnc.add_entropy("808080808080808080808080808080808080808080808080", 192, 16);
    expected = "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always";
    actual = mnc.get_word_list();
    ASSERT_EQ(actual, expected);
    expected_seed = Bitstream("107d7c02a5aa6f38c58083ff74f04c607c2d2c0ecc55501dadd72d025b751bc27fe913ffb796f841c49b1d33b610cf0e91d3aa239027f5e99fe4ce9e5088cd65", 512, 16);
    actual_seed = mnc.get_seed("TREZOR");
    ASSERT_EQ(actual_seed, expected_seed);

    mnc = Mnemonic(192);
    mnc.add_entropy("ffffffffffffffffffffffffffffffffffffffffffffffff", 192, 16);
    expected = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when";
    actual = mnc.get_word_list();
    ASSERT_EQ(actual, expected);
    expected_seed = Bitstream("0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a76379b43348d952e2265b4cd129090758b3e3c2c49103b5051aac2eaeb890a528", 512, 16);
    actual_seed = mnc.get_seed("TREZOR");
    ASSERT_EQ(actual_seed, expected_seed);

    mnc = Mnemonic(256);
    mnc.add_entropy("0000000000000000000000000000000000000000000000000000000000000000", 256, 16);
    expected = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    actual = mnc.get_word_list();
    ASSERT_EQ(actual, expected);
    expected_seed = Bitstream("bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8", 512, 16);
    actual_seed = mnc.get_seed("TREZOR");
    ASSERT_EQ(actual_seed, expected_seed);

    mnc = Mnemonic(256);
    mnc.add_entropy("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", 256, 16);
    expected = "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title";
    actual = mnc.get_word_list();
    ASSERT_EQ(actual, expected);
    expected_seed = Bitstream("bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87", 512, 16);
    actual_seed = mnc.get_seed("TREZOR");
    ASSERT_EQ(actual_seed, expected_seed);

    mnc = Mnemonic(256);
    mnc.add_entropy("8080808080808080808080808080808080808080808080808080808080808080", 256, 16);
    expected = "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless";
    actual = mnc.get_word_list();
    ASSERT_EQ(actual, expected);
    expected_seed = Bitstream("c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f", 512, 16);
    actual_seed = mnc.get_seed("TREZOR");
    ASSERT_EQ(actual_seed, expected_seed);

    mnc = Mnemonic(256);
    mnc.add_entropy("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 256, 16);
    expected = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote";
    actual = mnc.get_word_list();
    ASSERT_EQ(actual, expected);
    expected_seed = Bitstream("dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad", 512, 16);
    actual_seed = mnc.get_seed("TREZOR");
    ASSERT_EQ(actual_seed, expected_seed);

    mnc = Mnemonic(128);
    mnc.add_entropy("9e885d952ad362caeb4efe34a8e91bd2", 128, 16);
    expected = "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic";
    actual = mnc.get_word_list();
    ASSERT_EQ(actual, expected);
    expected_seed = Bitstream("274ddc525802f7c828d8ef7ddbcdc5304e87ac3535913611fbbfa986d0c9e5476c91689f9c8a54fd55bd38606aa6a8595ad213d4c9c9f9aca3fb217069a41028", 512, 16);
    actual_seed = mnc.get_seed("TREZOR");
    ASSERT_EQ(actual_seed, expected_seed);

    mnc = Mnemonic(192);
    mnc.add_entropy("6610b25967cdcca9d59875f5cb50b0ea75433311869e930b", 192, 16);
    expected = "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog";
    actual = mnc.get_word_list();
    ASSERT_EQ(actual, expected);
    expected_seed = Bitstream("628c3827a8823298ee685db84f55caa34b5cc195a778e52d45f59bcf75aba68e4d7590e101dc414bc1bbd5737666fbbef35d1f1903953b66624f910feef245ac", 512, 16);
    actual_seed = mnc.get_seed("TREZOR");
    ASSERT_EQ(actual_seed, expected_seed);

    mnc = Mnemonic(256);
    mnc.add_entropy("68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c", 256, 16);
    expected = "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length";
    actual = mnc.get_word_list();
    ASSERT_EQ(actual, expected);
    expected_seed = Bitstream("64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440", 512, 16);
    actual_seed = mnc.get_seed("TREZOR");
    ASSERT_EQ(actual_seed, expected_seed);

    mnc = Mnemonic(128);
    mnc.add_entropy("c0ba5a8e914111210f2bd131f3d5e08d", 128, 16);
    expected = "scheme spot photo card baby mountain device kick cradle pact join borrow";
    actual = mnc.get_word_list();
    ASSERT_EQ(actual, expected);
    expected_seed = Bitstream("ea725895aaae8d4c1cf682c1bfd2d358d52ed9f0f0591131b559e2724bb234fca05aa9c02c57407e04ee9dc3b454aa63fbff483a8b11de949624b9f1831a9612", 512, 16);
    actual_seed = mnc.get_seed("TREZOR");
    ASSERT_EQ(actual_seed, expected_seed);

    mnc = Mnemonic(192);
    mnc.add_entropy("6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3", 192, 16);
    expected = "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave";
    actual = mnc.get_word_list();
    ASSERT_EQ(actual, expected);
    expected_seed = Bitstream("fd579828af3da1d32544ce4db5c73d53fc8acc4ddb1e3b251a31179cdb71e853c56d2fcb11aed39898ce6c34b10b5382772db8796e52837b54468aeb312cfc3d", 512, 16);
    actual_seed = mnc.get_seed("TREZOR");
    ASSERT_EQ(actual_seed, expected_seed);

    mnc = Mnemonic(256);
    mnc.add_entropy("9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863", 256, 16);
    expected = "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside";
    actual = mnc.get_word_list();
    ASSERT_EQ(actual, expected);
    expected_seed = Bitstream("72be8e052fc4919d2adf28d5306b5474b0069df35b02303de8c1729c9538dbb6fc2d731d5f832193cd9fb6aeecbc469594a70e3dd50811b5067f3b88b28c3e8d", 512, 16);
    actual_seed = mnc.get_seed("TREZOR");
    ASSERT_EQ(actual_seed, expected_seed);

    mnc = Mnemonic(128);
    mnc.add_entropy("23db8160a31d3e0dca3688ed941adbf3", 128, 16);
    expected = "cat swing flag economy stadium alone churn speed unique patch report train";
    actual = mnc.get_word_list();
    ASSERT_EQ(actual, expected);
    expected_seed = Bitstream("deb5f45449e615feff5640f2e49f933ff51895de3b4381832b3139941c57b59205a42480c52175b6efcffaa58a2503887c1e8b363a707256bdd2b587b46541f5", 512, 16);
    actual_seed = mnc.get_seed("TREZOR");
    ASSERT_EQ(actual_seed, expected_seed);

    mnc = Mnemonic(192);
    mnc.add_entropy("8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0", 192, 16);
    expected = "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access";
    actual = mnc.get_word_list();
    ASSERT_EQ(actual, expected);
    expected_seed = Bitstream("4cbdff1ca2db800fd61cae72a57475fdc6bab03e441fd63f96dabd1f183ef5b782925f00105f318309a7e9c3ea6967c7801e46c8a58082674c860a37b93eda02", 512, 16);
    actual_seed = mnc.get_seed("TREZOR");
    ASSERT_EQ(actual_seed, expected_seed);

    mnc = Mnemonic(256);
    mnc.add_entropy("066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad", 256, 16);
    expected = "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform";
    actual = mnc.get_word_list();
    ASSERT_EQ(actual, expected);
    expected_seed = Bitstream("26e975ec644423f4a4c4f4215ef09b4bd7ef924e85d1d17c4cf3f136c2863cf6df0a475045652c57eb5fb41513ca2a2d67722b77e954b4b3fc11f7590449191d", 512, 16);
    actual_seed = mnc.get_seed("TREZOR");
    ASSERT_EQ(actual_seed, expected_seed);

    mnc = Mnemonic(128);
    mnc.add_entropy("f30f8c1da665478f49b001d94c5fc452", 128, 16);
    expected = "vessel ladder alter error federal sibling chat ability sun glass valve picture";
    actual = mnc.get_word_list();
    ASSERT_EQ(actual, expected);
    expected_seed = Bitstream("2aaa9242daafcee6aa9d7269f17d4efe271e1b9a529178d7dc139cd18747090bf9d60295d0ce74309a78852a9caadf0af48aae1c6253839624076224374bc63f", 512, 16);
    actual_seed = mnc.get_seed("TREZOR");
    ASSERT_EQ(actual_seed, expected_seed);

    mnc = Mnemonic(192);
    mnc.add_entropy("c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05", 192, 16);
    expected = "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump";
    actual = mnc.get_word_list();
    ASSERT_EQ(actual, expected);
    expected_seed = Bitstream("7b4a10be9d98e6cba265566db7f136718e1398c71cb581e1b2f464cac1ceedf4f3e274dc270003c670ad8d02c4558b2f8e39edea2775c9e232c7cb798b069e88", 512, 16);
    actual_seed = mnc.get_seed("TREZOR");
    ASSERT_EQ(actual_seed, expected_seed);

    mnc = Mnemonic(256);
    mnc.add_entropy("f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f", 256, 16);
    expected = "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold";
    actual = mnc.get_word_list();
    ASSERT_EQ(actual, expected);
    expected_seed = Bitstream("01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998", 512, 16);
    actual_seed = mnc.get_seed("TREZOR");
    ASSERT_EQ(actual_seed, expected_seed);
}
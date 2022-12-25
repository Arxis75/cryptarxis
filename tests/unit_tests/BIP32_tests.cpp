#include <gtest/gtest.h>
#include <crypto/bips.h>

TEST(BIP32Tests, TestBIP32_vector1)
{
    // seed: 0x000102030405060708090a0b0c0d0e0f
    // path: m
    Bitstream seed = Bitstream("0x000102030405060708090a0b0c0d0e0f", 128, 16);
    Privkey x(seed, "m");
    auto expected = Bitstream("0xe8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35", 256 ,16);
    auto actual = x.getSecret();
    ASSERT_EQ(actual, expected);
    expected = Bitstream("0x0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2", 256+8, 16);
    actual = x.getPubKey().getKey(Pubkey::Format::PREFIXED_X);
    ASSERT_EQ(actual, expected);

    // seed: 0x000102030405060708090a0b0c0d0e0f
    // path: m/0'
    x = Privkey(x, 0, true);
    expected = Bitstream("0xedb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea", 256 ,16);
    actual = x.getSecret();
    ASSERT_EQ(actual, expected);
    expected = Bitstream("0x035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56", 256+8, 16);
    actual = x.getPubKey().getKey(Pubkey::Format::PREFIXED_X);
    ASSERT_EQ(actual, expected);

    // seed: 0x000102030405060708090a0b0c0d0e0f
    // path: m/0'/1
    x = Privkey(x, 1, false);
    expected = Bitstream("0x3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368", 256 ,16);
    actual = x.getSecret();
    ASSERT_EQ(actual, expected);
    expected = Bitstream("0x03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c", 256+8, 16);
    actual = x.getPubKey().getKey(Pubkey::Format::PREFIXED_X);
    ASSERT_EQ(actual, expected);

    // seed: 0x000102030405060708090a0b0c0d0e0f
    // path: m/0'/1/2'
    x = Privkey(x, 2, true);
    expected = Bitstream("0xcbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca", 256 ,16);
    actual = x.getSecret();
    ASSERT_EQ(actual, expected);
    expected = Bitstream("0x0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2", 256+8, 16);
    actual = x.getPubKey().getKey(Pubkey::Format::PREFIXED_X);
    ASSERT_EQ(actual, expected);

    // seed: 0x000102030405060708090a0b0c0d0e0f
    // path: m/0'/1/2'/2
    x = Privkey(x, 2, false);
    expected = Bitstream("0x0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4", 256 ,16);
    actual = x.getSecret();
    ASSERT_EQ(actual, expected);
    expected = Bitstream("0x02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29", 256+8, 16);
    actual = x.getPubKey().getKey(Pubkey::Format::PREFIXED_X);
    ASSERT_EQ(actual, expected);

    // seed: 0x000102030405060708090a0b0c0d0e0f
    // path: m/0'/1/2'/2/1000000000
    x = Privkey(x, 1000000000, false);
    expected = Bitstream("0x471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8", 256 ,16);
    actual = x.getSecret();
    ASSERT_EQ(actual, expected);
    expected = Bitstream("0x022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011", 256+8, 16);
    actual = x.getPubKey().getKey(Pubkey::Format::PREFIXED_X);
    ASSERT_EQ(actual, expected);
}

TEST(BIP32Tests, TestBIP32_vector2)
{
    // seed: 0xfffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542
    // path: m
    Bitstream seed = Bitstream("0xfffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542", 512, 16);
    Privkey x(seed, "m");
    auto expected = Bitstream("0x4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e", 256 ,16);
    auto actual = x.getSecret();
    ASSERT_EQ(actual, expected);
    expected = Bitstream("0x03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7", 256+8, 16);
    actual = x.getPubKey().getKey(Pubkey::Format::PREFIXED_X);
    ASSERT_EQ(actual, expected);

    // seed: 0xfffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542
    // path: m/0
    x = Privkey(x, 0, false);
    expected = Bitstream("0xabe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e", 256 ,16);
    actual = x.getSecret();
    ASSERT_EQ(actual, expected);
    expected = Bitstream("0x02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea", 256+8, 16);
    actual = x.getPubKey().getKey(Pubkey::Format::PREFIXED_X);
    ASSERT_EQ(actual, expected);

    // seed: 0xfffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542
    // path: m/0/2147483647'
    x = Privkey(x, 2147483647, true);
    expected = Bitstream("0x877c779ad9687164e9c2f4f0f4ff0340814392330693ce95a58fe18fd52e6e93", 256 ,16);
    actual = x.getSecret();
    ASSERT_EQ(actual, expected);
    expected = Bitstream("0x03c01e7425647bdefa82b12d9bad5e3e6865bee0502694b94ca58b666abc0a5c3b", 256+8, 16);
    actual = x.getPubKey().getKey(Pubkey::Format::PREFIXED_X);
    ASSERT_EQ(actual, expected);

    // seed: 0xfffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542
    // path: m/0/2147483647'/1
    x = Privkey(x, 1, false);
    expected = Bitstream("0x704addf544a06e5ee4bea37098463c23613da32020d604506da8c0518e1da4b7", 256 ,16);
    actual = x.getSecret();
    ASSERT_EQ(actual, expected);
    expected = Bitstream("0x03a7d1d856deb74c508e05031f9895dab54626251b3806e16b4bd12e781a7df5b9", 256+8, 16);
    actual = x.getPubKey().getKey(Pubkey::Format::PREFIXED_X);
    ASSERT_EQ(actual, expected);

    // seed: 0xfffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542
    // path: m/0/2147483647'/1/2147483646'
    x = Privkey(x, 2147483646, true);
    expected = Bitstream("0xf1c7c871a54a804afe328b4c83a1c33b8e5ff48f5087273f04efa83b247d6a2d", 256 ,16);
    actual = x.getSecret();
    ASSERT_EQ(actual, expected);
    expected = Bitstream("0x02d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0", 256+8, 16);
    actual = x.getPubKey().getKey(Pubkey::Format::PREFIXED_X);
    ASSERT_EQ(actual, expected);

    // seed: 0xfffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542
    // path: m/0/2147483647'/1/2147483646'/2
    x = Privkey(x, 2, false);
    expected = Bitstream("0xbb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac23", 256 ,16);
    actual = x.getSecret();
    ASSERT_EQ(actual, expected);
    expected = Bitstream("0x024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c", 256+8, 16);
    actual = x.getPubKey().getKey(Pubkey::Format::PREFIXED_X);
    ASSERT_EQ(actual, expected);
}

TEST(BIP32Tests, TestBIP32_vector3)
{
    // seed: 0x4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be
    // path: m
    Bitstream seed = Bitstream("0x4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be", 512, 16);
    Privkey x(seed, "m");
    auto expected = Bitstream("0x00ddb80b067e0d4993197fe10f2657a844a384589847602d56f0c629c81aae32", 256 ,16);
    auto actual = x.getSecret();
    ASSERT_EQ(actual, expected);
    expected = Bitstream("0x03683af1ba5743bdfc798cf814efeeab2735ec52d95eced528e692b8e34c4e5669", 256+8, 16);
    actual = x.getPubKey().getKey(Pubkey::Format::PREFIXED_X);
    ASSERT_EQ(actual, expected);

    // seed: 4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be
    // path: m/0'
    x = Privkey(x, 0, true);
    expected = Bitstream("0x491f7a2eebc7b57028e0d3faa0acda02e75c33b03c48fb288c41e2ea44e1daef", 256 ,16);
    actual = x.getSecret();
    ASSERT_EQ(actual, expected);
    expected = Bitstream("0x026557fdda1d5d43d79611f784780471f086d58e8126b8c40acb82272a7712e7f2", 256+8, 16);
    actual = x.getPubKey().getKey(Pubkey::Format::PREFIXED_X);
    ASSERT_EQ(actual, expected);
}

TEST(BIP32Tests, TestBIP32_vector4)
{
    // seed: 0x3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678
    // path: m
    Bitstream seed = Bitstream("0x3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678", 256, 16);
    Privkey x(seed, "m");
    auto expected = Bitstream("0x12c0d59c7aa3a10973dbd3f478b65f2516627e3fe61e00c345be9a477ad2e215", 256 ,16);
    auto actual = x.getSecret();
    ASSERT_EQ(actual, expected);
    expected = Bitstream("0x026f6fedc9240f61daa9c7144b682a430a3a1366576f840bf2d070101fcbc9a02d", 256+8, 16);
    actual = x.getPubKey().getKey(Pubkey::Format::PREFIXED_X);
    ASSERT_EQ(actual, expected);

    // seed: 4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be
    // path: m/0'
    x = Privkey(x, 0, true);
    expected = Bitstream("0x00d948e9261e41362a688b916f297121ba6bfb2274a3575ac0e456551dfd7f7e", 256 ,16);
    actual = x.getSecret();
    ASSERT_EQ(actual, expected);
    expected = Bitstream("0x039382d2b6003446792d2917f7ac4b3edf079a1a94dd4eb010dc25109dda680a9d", 256+8, 16);
    actual = x.getPubKey().getKey(Pubkey::Format::PREFIXED_X);
    ASSERT_EQ(actual, expected);

    // seed: 4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be
    // path: m/0'/1'
    x = Privkey(x, 1, true);
    expected = Bitstream("0x3a2086edd7d9df86c3487a5905a1712a9aa664bce8cc268141e07549eaa8661d", 256 ,16);
    actual = x.getSecret();
    ASSERT_EQ(actual, expected);
    expected = Bitstream("0x032edaf9e591ee27f3c69c36221e3c54c38088ef34e93fbb9bb2d4d9b92364cbbd", 256+8, 16);
    actual = x.getPubKey().getKey(Pubkey::Format::PREFIXED_X);
    ASSERT_EQ(actual, expected);
}
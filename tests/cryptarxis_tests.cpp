#include <crypto/bips.h>
#include <gtest/gtest.h>

TEST(BIP39Tests, TestEntropy_One)
{
    const auto expected = 0;
    const auto actual = 0;
    ASSERT_EQ(actual, expected);
}

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
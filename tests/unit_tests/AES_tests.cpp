#include <gtest/gtest.h>
#include <crypto/bips.h>
#include <crypto/AES.h>

TEST(AES_tests, CTR_DiscV5_vectors)
{
    //https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire-test-vectors.md

    ByteStream who_are_you("00000000000000000000000000000000088b3d434277464933a1ccc59f5967ad1d6035f15e528627dde75cd68292f9e6c27d6b66c8100a873fcbaed4e16b8d", 63, 16);
    ByteStream packet = who_are_you;
    
    ByteStream masking_iv(&packet[0], 16);
    ByteStream masked_header(&packet[16], packet.byteSize() - 16);
    ByteStream header(Integer::zero, masked_header.byteSize());

    ByteStream dest_node_id("0xbbbb9d047f0488c0b5a93c1c3f2d8bafc7c8ff337024a55434a0d0555de64db9", 32, 16);
    ByteStream masking_key(&dest_node_id[0], 16);

    ctr_decrypt(masked_header, masked_header.byteSize(),
                masking_key,
                masking_iv, masking_iv.byteSize(),
                header);

    //protocol-id
    ByteStream expected = ByteStream("discv5");
    ByteStream actual = header.pop_front(6);
    ASSERT_EQ(actual, expected);

    //version
    expected = ByteStream(0x0001, 2);
    actual = header.pop_front(2);
    ASSERT_EQ(actual, expected);

    //flag
    expected = ByteStream(1);
    actual = header.pop_front(1);
    ASSERT_EQ(actual, expected);

    //nonce
    expected = ByteStream("0x0102030405060708090a0b0c", 12, 16);
    actual = header.pop_front(12);
    ASSERT_EQ(actual, expected);

    //authdata-size
    expected = ByteStream(24, 2);
    actual = header.pop_front(2);
    ASSERT_EQ(actual, expected);

    //id-nonce
    expected = ByteStream("0x0102030405060708090a0b0c0d0e0f10", 16, 16);
    actual = header.pop_front(16);
    ASSERT_EQ(actual, expected);

    //enr-seq
    expected = ByteStream(Integer::zero, 8);
    actual = header.pop_front(8);
    ASSERT_EQ(actual, expected);
}

TEST(AES_tests, GCM_DiscV5_vectors)
{
    //https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire-test-vectors.md

    ByteStream masking_iv("0x00000000000000000000000000000000", 16);
    ByteStream masked_header("0x088b3d4342774649325f313964a39e55ea96c005ad52be8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d34c4f53245d08dab84102ed931f66d1492acb308fa1c6715b9d139b81acbdcc", 79, 16);    
    ByteStream header("0x646973637635000100ffffffffffffffffffffffff0020aaaa8419e9f49d0083561b48287df592939a8d19947d8c0ef88f2a4856a69fbb", 55, 16);
    ByteStream session_key("0x00000000000000000000000000000000", 16, 16);

    ByteStream aad;
    aad.push_back(masking_iv);
    aad.push_back(header);

    ByteStream nonce(&header[9], 12);
    ByteStream ciphertext(&masked_header[header.byteSize()], masked_header.byteSize() - header.byteSize() - 16);
    ByteStream tag(&masked_header[masked_header.byteSize() - 16], 16);

    ByteStream pt(Integer::zero, ciphertext.byteSize());

    gcm_decrypt(ciphertext, ciphertext.byteSize(),
                aad, aad.byteSize(),
                tag,
                session_key,
                nonce, nonce.byteSize(),
                pt);

    bool expected = ByteStream("0x01c6840000000102", 8, 16);
    bool actual = pt;
    ASSERT_EQ(actual, expected);

    ciphertext = ByteStream("0x00", ciphertext.byteSize(), 16);
    tag = ByteStream("0x00", 16, 16);

    gcm_encrypt(pt, pt.byteSize(),
                aad, aad.byteSize(),
                session_key, nonce, nonce.byteSize(),
                ciphertext, tag);

    expected = ByteStream("0xb84102ed931f66d1", 8, 16);
    actual = ciphertext;
    ASSERT_EQ(actual, expected);
    expected = ByteStream("0x492acb308fa1c6715b9d139b81acbdcc", 16, 16);
    actual = tag;
    ASSERT_EQ(actual, expected);
}


TEST(AES_tests, HKDF_DiscV5_vectors)
{
    //https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire-test-vectors.md

    ByteStream challenge_data("0x000000000000000000000000000000006469736376350001010102030405060708090a0b0c00180102030405060708090a0b0c0d0e0f100000000000000000", 63, 16);

    Privkey node_a_secret(ByteStream("0xeef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f", 32, 16));
    Privkey node_b_secret(ByteStream("0x66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb1cde628", 32, 16));
    Pubkey node_b_pub_key(node_b_secret.getPubKey());
    
    ByteStream node_id_a(node_a_secret.getPubKey().getID());
    ByteStream node_id_b(node_b_secret.getPubKey().getID());
    
    Privkey ephemeral_secret(ByteStream("0xfb757dc581730490a1d7a00deea65e9b1936924caaea8f44d476014856b68736", 32, 16));

    Pubkey ecdh(Secp256k1::GetInstance().p_scalar(node_b_pub_key.getPoint(), ephemeral_secret.getSecret()));
    ByteStream shared_secret = ecdh.getKey(Pubkey::Format::PREFIXED_X);
    
    ByteStream kdf_info("discovery v5 key agreement");
    kdf_info.push_back(node_id_a);
    kdf_info.push_back(node_id_b);

    ByteStream new_key(Integer::zero, 32);
    int retval = hkdf_derive( shared_secret, shared_secret.byteSize(),
                            challenge_data, challenge_data.byteSize(),
                            kdf_info, kdf_info.byteSize(),
                            new_key );

    ByteStream initiator_key(&new_key[0], 16);
    ByteStream recipient_key(&new_key[16], 16);

    ByteStream expected = ByteStream("0xdccc82d81bd610f4f76d3ebe97a40571", 16, 16);
    ByteStream actual = initiator_key;
    ASSERT_EQ(actual, expected);  

    expected = ByteStream("0xac74bb8773749920b0d3a8881c173ec5", 16, 16);
    actual = recipient_key;
    ASSERT_EQ(actual, expected);
}
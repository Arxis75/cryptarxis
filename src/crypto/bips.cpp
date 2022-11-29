#include <Common.h>

#include "EllipticCurve.h"
#include "bips.h"
#include "bip39_dictionnary.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <ethash/keccak.hpp>

using namespace BIP39;
using namespace BIP32;
using namespace ethash;

//----------------------------------------------------------- BIP32 -----------------------------------------------------------------
extpubkey::extpubkey(Secp256k1& curve, Integer k, Integer cc)   //from Curve + private key
    : key(curve.Gmul(k))
    , chaincode(cc)
{}

const Integer extpubkey::getKey(size_t size) const
{   
    Integer publicKey = key.getX();

    Integer prefix = 0;
    if( size == 33 )
        prefix = ((key.getY() % 2) ? 0x03 : 0x02);
    else if(size == 65)
        prefix = 0x04;

    publicKey += (prefix << 256);
    
    if( size == 64 | size == 65 )
    {
        publicKey <<= 256;
        publicKey += key.getY();
    }
    return publicKey;
}

Integer extpubkey::getAddress() const
{
    Integer GI_address = 0;
    uint8_t address[20];
    uint8_t data[64];
    GInteger_to_ByteArray(getKey(64), &data[0], 64);
    hash256 h = keccak256(data, 64);
    memcpy(address, &h.bytes[32 - 20], 20);
    ByteArray_to_GInteger(address, GI_address, 20);
    return GI_address;
}

extprivkey::extprivkey(const extprivkey& parent, const int32_t index, const bool hardened)
{
    assert(index >= 0);

    uint8_t parent_secret[33];
    GInteger_to_ByteArray(parent.getSecret(), parent_secret, 33);
    
    uint8_t parent_data[33 + 4];
    parent_data[33 + 0] = (reinterpret_cast<const uint8_t*>(&index))[3];
    parent_data[33 + 1] = (reinterpret_cast<const uint8_t*>(&index))[2];
    parent_data[33 + 2] = (reinterpret_cast<const uint8_t*>(&index))[1];
    parent_data[33 + 3] = (reinterpret_cast<const uint8_t*>(&index))[0];

    if(hardened) {
        memcpy(&parent_data[0], parent_secret, 33);
        parent_data[33 + 0] += 0x80;
    }
    else {
        uint8_t parent_pubkey[33];
        GInteger_to_ByteArray(parent.getExtPubKey().getKey(33), parent_pubkey, 33);
        memcpy(&parent_data[0], &parent_pubkey[0], 33);
    }

    uint8_t digest[64];
    uint32_t dilen;

    uint8_t parent_cc[32];
    GInteger_to_ByteArray(parent.getExtPubKey().getChainCode(), parent_cc, 32);

    unsigned char *res = ::HMAC(::EVP_sha512(),
                                reinterpret_cast<const char*>(parent_cc), 32,
                                parent_data, 33 + 4,
                                reinterpret_cast<unsigned char *>(digest), &dilen);
    if (res && dilen == 64)
    {
        cout << "BIP32 " << dec << index << (hardened ? "'" : "") << " raw (hex): " << b2a_hex(digest,64) << dec << endl;

        ByteArray_to_GInteger(&digest[0],secret, 32);
        secret += parent.getSecret();
        secret %= Secp256k1::GetInstance().getCurveOrder();

        Integer cc;
        ByteArray_to_GInteger(&digest[32], cc, 32);

        pubkey = new extpubkey(Secp256k1::GetInstance(), secret, cc);

        cout << "BIP32 " << index << (hardened ? "'" : "") << " chain code (hex): " << hex <<  pubkey->getChainCode() << dec << endl;
        cout << "BIP32 " << index << (hardened ? "'" : "") << " secret (hex): " << hex << secret << dec << endl;
        cout << "BIP32 " << index << (hardened ? "'" : "") << " public key (hex): " << hex << pubkey->getKey(33) << dec << endl << endl;
    }
}

extprivkey::extprivkey(const seed& s)
{
    // Cf https://www.openssl.org/docs/manmaster/man3/HMAC.html
    // Cf https://www.openssl.org/docs/manmaster/man3/EVP_sha512.html

    uint8_t digest[64];
    uint32_t dilen;

    unsigned char *res = ::HMAC(::EVP_sha512(),
                                "Bitcoin seed", 12,
                                s.get(), 64,
                                reinterpret_cast<unsigned char *>(digest), &dilen);
    if (res && dilen == 64)
    {
        ByteArray_to_GInteger(&digest[0], secret, 32);
        assert(secret > 0 && secret < Secp256k1::GetInstance().getCurveOrder());

        Integer cc;
        ByteArray_to_GInteger(&digest[32], cc, 32);
        
        pubkey = new extpubkey(Secp256k1::GetInstance(), secret, cc);

        cout << "BIP32 " << "Root chain code (hex): " << hex <<  pubkey->getChainCode() << dec << endl;
        cout << "BIP32 " << "Root secret (hex): " << hex << secret << dec << endl;
        cout << "BIP32 " << "Root public key (hex): " << hex << pubkey->getKey(33) << dec << endl << endl;

    }
}

extprivkey *extprivkey::derive(int32_t child_index, bool child_is_hardened)
{
    if (child)
        delete child;
    child = new extprivkey(*this, child_index, child_is_hardened);
    return child;
}

//----------------------------------------------------------- BIP39 -----------------------------------------------------------------
entropy::entropy()
    : current_bitsize(0)
{
    the_entropy.clear();
}

void entropy::add_n_bits_of_entropy(const uint32_t extra_e, const uint8_t n_bits)
{
    div_t d = div(current_bitsize, 32);
    if (!d.rem)
        the_entropy.push_back(extra_e);
    else
    {
        uint8_t current_elem_new_bits_count = min(32 - d.rem, (int32_t)n_bits);
        uint8_t next_elem_new_bits_count = max(d.rem + n_bits - 32, 0);
        the_entropy[d.quot] <<= current_elem_new_bits_count;
        the_entropy[d.quot] += (extra_e >> next_elem_new_bits_count);
        if (next_elem_new_bits_count)
            the_entropy.push_back(extra_e & (0xFFFFFFFF >> (32 - next_elem_new_bits_count)));
    }
    current_bitsize += n_bits;
}

void entropy::clear()
{
    the_entropy.clear();
    current_bitsize = 0;
}

bool entropy::get_nth_word(const uint8_t n, const uint8_t word_bitsize, uint32_t &nth_word) const
{
    bool res = false;
    if (word_bitsize <= 32)
    {
        div_t index = div(n * word_bitsize, 32);
        if (index.quot < the_entropy.size())
        {
            uint8_t tail_padding = max(((index.quot + 1) << 5) - current_bitsize, 0); // the_entropy last element size might be < 32 bits
            uint8_t nthwbitsize = word_bitsize - max((index.quot << 5) + index.rem + word_bitsize - (int)current_bitsize, 0);
            int8_t next_elem_new_bits_count = index.rem + nthwbitsize - (32 - tail_padding);
            uint32_t nthw = the_entropy[index.quot] & (0xFFFFFFFF >> (index.rem + tail_padding));
            if (next_elem_new_bits_count < 0)
                nthw >>= -next_elem_new_bits_count;
            else if (next_elem_new_bits_count > 0)
            {
                tail_padding = max(((index.quot + 2) << 5) - current_bitsize, 0);
                nthw <<= next_elem_new_bits_count;
                nthw += the_entropy[index.quot + 1] >> ((32 - tail_padding) - next_elem_new_bits_count);
            }
            nth_word = nthw;
            res = true;
        }
    }
    return res;
}

uint8_t entropy::checksum(const uint8_t checksum_bitsize) const
{
    assert(checksum_bitsize <= 8);
    assert(current_bitsize % 32 == 0);
    uint8_t array2hash[current_bitsize >> 3];
    Vector_to_ByteArray(the_entropy, array2hash);
    unsigned char digest[32];
    SHA256(array2hash, sizeof(array2hash), digest);
    return digest[0] >> (8 - checksum_bitsize);
}

void entropy::print() const
{
    // TODO: display leading zeroes for each word
    div_t d = div(current_bitsize, 32);
    int i;
    cout << "0x";
    for (i = 0; i < d.quot; i++)
        cout << hex << the_entropy[i];
    cout << " (" << dec << (d.quot << 5) << " bits)";
    if (d.rem)
        cout << " + 0x" << hex << the_entropy[d.quot] << " (" << dec << d.rem << " bits)";
    cout << endl;
}

mnemonic::mnemonic(const size_t entropy_bitsize, const vector<string> *dictionnary)
{
    div_t d;
    dic = (dictionnary ? dictionnary : &BIP39::Dictionary::WordList_english);
    assert(dic->size() > 1); // at least 2 elements
    // TOD: verify each element of the dictionnary is unique

    went = log2(dic->size());
    assert(went <= 32); // max word entropy = 32 bits

    ent = entropy_bitsize;
    assert(ent >= 128); // for security
    d = div(ent, 32);
    assert(!d.rem); // multiple of 32

    d = div(ent, (int)went);
    ms = d.quot + 1; // 1 extra word for checksum/alignment
    cs = went - d.rem;
}

bool mnemonic::add_word(const string &word)
{
    bool res = false;
    // TODO: remove case-sensitive
    vector<string>::const_iterator dic_it;
    dic_it = find(dic->begin(), dic->end(), word);
    if (dic_it != dic->end() && e.getCurrentBitSize() < ent)
    {
        bool is_last_word = (e.getCurrentBitSize() + went > ent);
        uint32_t controlled_went = went;
        if (is_last_word)
            controlled_went -= cs;
        uint32_t index = distance(dic->begin(), dic_it);
        entropy tmp_e(e);
        tmp_e.add_n_bits_of_entropy(index >> (went - controlled_went), controlled_went);
        if (!is_last_word || tmp_e.checksum(cs) == (index & (0xFF >> (8 - cs))))
        {
            e = tmp_e;
            res = true;
        }
    }
    if (!res)
        cout << "invalid word addition!" << endl;
    return res;
}

bool mnemonic::set_full_word_list(const string &list)
{
    bool res = false;
    vector<string> v = split(list, " ");
    if (v.size() == ms)
        for (int i = 0; i < v.size(); i++)
        {
            res = add_word(v[i]);
            if (!res)
            {
                clear();
                break;
            }
        }
    return res;
}

bool mnemonic::is_valid() const
{
    return (e.getCurrentBitSize() == ent);
}

void mnemonic::clear()
{
    e.clear();
}

const string mnemonic::get_word_list() const
{
    string ret("");
    uint32_t nth_word;
    div_t d = div(e.getCurrentBitSize(), went);
    for (int i = 0; i < d.quot; i++)
    {
        if (ret.size() > 0)
            ret += " ";
        if (e.get_nth_word(i, went, nth_word))
            ret += dic->at(nth_word);
    }
    if (d.rem && is_valid())
        ret += " " + get_last_word();
    return ret;
}

bool mnemonic::list_possible_last_word(vector<string> &list) const
{
    bool res = false;
    if (e.getCurrentBitSize() == went * (ms - 1))
    {
        list.clear();
        for (int i = 0; i < (1 << (went - cs)); i++)
        {
            entropy tmp(e);
            tmp.add_n_bits_of_entropy(i, went - cs);
            list.push_back(dic->at((i << cs) + tmp.checksum(cs)));
        }
        res = true;
    }
    return res;
}

const string mnemonic::get_last_word() const
{
    string ret("");
    if (is_valid())
    {
        uint32_t nthw;
        if (e.get_nth_word(ms - 1, went, nthw))
            ret = dic->at((nthw << cs) + e.checksum(cs));
    }
    return ret;
}

void mnemonic::print(bool as_index_list) const
{
    if (as_index_list)
        e.print();
    else
        cout << get_word_list() << endl;
}

seed::seed(const BIP39::mnemonic& mnc, const string& pwd)
{
    if (mnc.is_valid())
    {
        const string pass = mnc.get_word_list();
        char salt[8 + pwd.size()];
        strcpy(salt, "mnemonic");
        strcat(salt, pwd.c_str()); // salt = "mnemonic" + password
        
        int a = strlen(reinterpret_cast<const char *>(salt));

        // Cf https://www.openssl.org/docs/manmaster/man3/PKCS5_PBKDF2_HMAC.html

        PKCS5_PBKDF2_HMAC( pass.c_str(), pass.size(),
                           reinterpret_cast<const unsigned char *>(salt), strlen(reinterpret_cast<const char *>(salt)),
                           2048,
                           EVP_sha512(),
                           64,
                           the_seed );
    }
}

void seed::print() const
{
    cout << b2a_hex(the_seed, sizeof(the_seed)) << endl;
}

/*unsigned char* sha256( const unsigned char* input, const size_t input_size,
                       char* hexResult, uint8_t* binResult )
{
    //Cf https://www.openssl.org/docs/manmaster/man3/SHA256.html

    unsigned char digest[_32_BYTES];

    unsigned char* ret = SHA256(input, input_size, digest);

    assert(ret);

    unsigned int i;
    for (i = 0; i < _32_BYTES; i++)
    {
        sprintf(hexResult + (i * 2), "%02x", 255 & digest[i]);
        binResult[i] = digest[i];
    };
    hexResult[_64_BYTES] = 0x00;

    return ret;
}*/

#pragma once

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <ethash/keccak.hpp>

#include "secp256k1/Common.h"
#include "secp256k1/Point.h"
#include "secp256k1/Curve.h"
#include "secp256k1/EllipticCurve.h"

#include "bip39_dictionnary.h"

#include <bitset>
#include <algorithm>

using namespace std;
using namespace Givaro;

static char hexa[] = "0123456789ABCDEF"; 

typedef enum ARRAY_SIZE {
    _4_BYTES = 4,
    _20_BYTES = 20,
    _32_BYTES = 32,
    _33_BYTES = 33,
    _COMPRESSED_33_BYTES = 33,
    _64_BYTES = 64,
    _UNCOMPRESSED_64_BYTES = 64,
    _UNCOMPRESSED_65_BYTES = 65,
    _128_BYTES = 128
} PUBKEY_FORMAT;

int pbkdf2_hmac_sha512( const char* pass,
                        const unsigned char* salt,
                        char* hexResult, uint8_t* binResult)
{
    //Cf https://www.openssl.org/docs/manmaster/man3/PKCS5_PBKDF2_HMAC.html

    unsigned char digest[_64_BYTES];

    int ret = PKCS5_PBKDF2_HMAC( pass, strlen(pass),
                                 salt, strlen(reinterpret_cast<const char *>(salt)),
                                 2048,
                                 EVP_sha512(),
                                 sizeof(digest),
                                 digest );
    assert(ret);

    unsigned int i;
    for (i = 0; i < _64_BYTES; i++)
    {
        sprintf(hexResult + (i * 2), "%02x", 255 & digest[i]);
        binResult[i] = digest[i];
    };
    hexResult[_128_BYTES] = 0x00;
    
    return ret;
}

unsigned char* hmac_sha512( const char* key, const size_t klen,
                            const uint8_t* data, const size_t dlen,
                            char* hexResult, uint8_t* binResult ) 
{
    //Cf https://www.openssl.org/docs/manmaster/man3/HMAC.html
    //Cf https://www.openssl.org/docs/manmaster/man3/EVP_sha512.html

    unsigned char digest[_64_BYTES];
    uint32_t dilen;

    unsigned char* ret = ::HMAC( ::EVP_sha512(),
                                 key, klen,
                                 data, dlen,
                                 digest, &dilen );
    
    assert(ret && dilen == _64_BYTES);

    unsigned int i;
    for (i = 0; i < _64_BYTES; i++)
    {
        sprintf(hexResult + (i * 2), "%02x", 255 & digest[i]);
        binResult[i] = digest[i];
    };
    hexResult[_128_BYTES] = 0x00;

    return ret;
}

unsigned char* sha256( const unsigned char* input, const size_t input_size,
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
}

string b2a_hex(const uint8_t* p, const size_t n) {
    static const char hex[] = "0123456789abcdef";
    string res;
    res.reserve(n * 2);

    for (auto end = p + n; p != end; ++p) {
        const uint8_t v = (*p);
        res += hex[(v >> 4) & 0x0F];
        res += hex[v & 0x0F];
    }

    return res;
}

void ByteArray_to_GInteger(const uint8_t* input, Integer &output, const size_t input_size) {
    output = 0;
    if(input_size>0)
    {
        output = input[0];
        if(input_size>1)
        {
            int i;
            uint32_t shift = 256;
            for(i=1;i<input_size;i++)
            {
                output *= shift;
                output += input[i];
            }
        }
    }
}

void GInteger_to_ByteArray(const Integer input, uint8_t* output, const size_t output_size) {
    int i;
    Integer last_byte(0xFF);
    for(i=0;i<output_size;i++)
        output[i] = (input >> ((output_size-1-i) << 3)) & last_byte;
}

//TODO: specifier privatekey sur 32 ou 33 bytes
//      specifier format publickey (compressed, uncompressed bitcoin, uncompressed ethereum)
void getPublicKey( const uint8_t* secret, const ARRAY_SIZE secret_size,
                   uint8_t* publicKey, const ARRAY_SIZE publicKey_size,
                   uint8_t* address = 0 )
{
    assert( (secret_size == _32_BYTES || secret_size == _33_BYTES) &&
            (publicKey_size == _COMPRESSED_33_BYTES || publicKey_size == _UNCOMPRESSED_64_BYTES || publicKey_size == _UNCOMPRESSED_65_BYTES) );
    /**
    ** y^2 = x^3 + 7 
    **/
    EllipticCurve ecc( Integer("115792089237316195423570985008687907853269984665640564039457584007908834671663"),
                    Integer("0"),
                    Integer("7") );

    //ecc.print();

    Point G( Integer("55066263022277343669578718895168534326250603453777594175500187360389116729240"),
            Integer("32670510020758816978083085130507043184471273380659243275938904335757337482424") );
    
    Point R;
    Integer k;
    ByteArray_to_GInteger(secret, k, secret_size);
    R = ecc._scalar(R,G,k);

    assert(ecc.verifyPoint(R));

    GInteger_to_ByteArray(R.getX(), publicKey, _32_BYTES);

    if( (publicKey_size == _UNCOMPRESSED_65_BYTES) |
        (publicKey_size == _COMPRESSED_33_BYTES) )
    {
        // shifts 1 Byte to input header
        memmove(&publicKey[1], &publicKey[0], _32_BYTES);    //not memcpy because copy on itself

        if( publicKey_size == _COMPRESSED_33_BYTES )
            publicKey[0] = ((R.getY() % 2) ? 0x03 : 0x02);
        else if(publicKey_size == _UNCOMPRESSED_65_BYTES)
            publicKey[0] = 0x04;
    }
    
    if( (publicKey_size == _UNCOMPRESSED_64_BYTES) |
        (publicKey_size == _UNCOMPRESSED_65_BYTES) )
    {
        int offset = (publicKey_size == _UNCOMPRESSED_64_BYTES ? _32_BYTES : _33_BYTES);
        GInteger_to_ByteArray(R.getY(), &publicKey[offset], _32_BYTES);
    }

    if( address )
    {
        Integer GI_data = (R.getX() << 256) + R.getY();
        uint8_t data[_64_BYTES];
        GInteger_to_ByteArray(GI_data, &data[0], _64_BYTES);
        ethash::hash256 h = ethash::keccak256(data, _64_BYTES);
        memcpy(address, &h.bytes[_32_BYTES - _20_BYTES], _20_BYTES);
    }
}

void ComputeBIP39Seed( const char* mnc, const char* pwd, const size_t pwd_size,
                       uint8_t* bip39_seed //, const ARRAY_SIZE bip39_seed_size = _64_BYTES
                     )
{
    char salt[8 + pwd_size];
    const uint32_t iterations = 2048;
    char hexResult[2*_64_BYTES+1];

    strcpy(salt,"mnemonic");
    strcat(salt,pwd);           // salt = "mnemonic" + password

    pbkdf2_hmac_sha512( mnc, reinterpret_cast<const unsigned char*>(salt),
                        hexResult, bip39_seed);

    cout << "BIP39 seed: " << hex << hexResult << endl << endl;

}
void ComputeBIP32RootKeys( const uint8_t* bip39_seed, //const ARRAY_SIZE bip39_seed_size = _64_BYTES,
                           uint8_t* root_chaincode, //ARRAY_SIZE child_chaincode = _32_BYTES,
                           uint8_t* root_secret, //ARRAY_SIZE child_secret_size = _33_BYTES,
                           uint8_t* root_pubkey //, ARRAY_SIZE child_secret_size = _COMPRESSED_33_BYTES,
                        )
{
    //---------------------------------------------- BIP 32 ----------------------------------------------  
    //  mnemonic                = "diamond recycle math quantum earn save nut spice hen rice soft wire artefact say twin drum rival live mask lens actress peasant abstract hint"
    //  BIP39 seed              = e8470fd3 c56c1f3a f5233b7a 1336caef 6a70b96a c7eebe51 6dbfd49e 4a35f1c1 00270616 219543a7 05e56acb a152c90b c970c5f0 e9b0fc8e 28590d9b 9b507651
    //  BIP32 Root key (m):
    //  version                 = 0x0488ade4
    //  depth                   =       0x00
    //  fingerprint             = 0x00000000
    //  index                   = 0x00000000
    //  chain code (32 Bytes)   =    0x5abe48ed 0d59a57a bff4d2b6 7758c579 556ba293 9c2b4f41 a0603cc0 210bbed5
    //  private key (33 Bytes)  = 0x00 2f04e7e1 85f4fd15 e391dcf5 f103d2c3 5d5b5088 d51f4f83 a938259d 16323e3b
    //  public key (33 bytes)   = 0x02 4847744b 02301d44 69d96b03 7df97431 666dcd84 0d8f1908 9d8b5e72 68f1873b
    //  checksum                = 0xdbfec215

    uint32_t output_size = _64_BYTES;
    char hexResult[2 *output_size + 1];
    uint8_t binResult[output_size];
    Integer GI_curve_order("115792089237316195423570985008687907852837564279074904382605163141518161494337");
    Integer GI_root_secret;

    hmac_sha512( "Bitcoin seed", 12,
                 bip39_seed, _64_BYTES,
                 hexResult, binResult);

    cout << "BIP32 Root(m) raw (hex): " << hex << hexResult << dec << endl;

    ByteArray_to_GInteger(&binResult[0], GI_root_secret, _32_BYTES);
    assert(GI_root_secret > 0 && GI_root_secret < GI_curve_order);

    root_secret[0] = 0x00;
    GInteger_to_ByteArray(GI_root_secret, &root_secret[1], _32_BYTES);

    memcpy(&root_chaincode[0], &binResult[32], _32_BYTES);
    
    getPublicKey(root_secret, _33_BYTES, root_pubkey, _COMPRESSED_33_BYTES);

    cout << "BIP32 m chain code (hex): " << hex << b2a_hex(root_chaincode, _32_BYTES) << dec << endl;
    cout << "BIP32 m secret (hex): " << hex << b2a_hex(root_secret, _33_BYTES) << dec << endl;
    cout << "BIP32 m public key (hex): " << hex << b2a_hex(root_pubkey, _COMPRESSED_33_BYTES) << dec << endl << endl;
}

void ComputeBIP32ChildKeys( const uint8_t* parent_chaincode, //const ARRAY_SIZE parent_chaincode = _32_BYTES,
                            const uint8_t* parent_secret, //const ARRAY_SIZE parent_secret_size = _33_BYTES,
                            uint8_t* child_chaincode, //ARRAY_SIZE child_chaincode = _32_BYTES,
                            uint8_t* child_secret, //ARRAY_SIZE child_secret_size = _33_BYTES,
                            uint8_t* child_pubkey, //ARRAY_SIZE child_secret_size = _COMPRESSED_33_BYTES,
                            int32_t index, bool hardened )
{
    //---------------------------------------------- BIP 32 ----------------------------------------------
    //  mnemonic                = "diamond recycle math quantum earn save nut spice hen rice soft wire artefact say twin drum rival live mask lens actress peasant abstract hint"
    //  BIP32 m/44' key:
    //  version                 = 0x0488ade4
    //  depth                   =       0x01
    //  fingerprint             = 0x1ac8b213
    //  index                   = 0x8000002c
    //  chain code (32 Bytes)   =    0x3bb166ac c0ac189e 4c118a60 1e88d177 de2a7bac a599a284 d652eee9 b3acd86f
    //  private key (33 Bytes)  = 0x00 ac25df2b 69a85cc6 f7fe10ed a8446cb6 9a798246 18c0a68e f78b084c 62e1c6d9
    //  public key (32 bytes)   = 0x02 922b732a 08a1b7ff 975235fc f14a7bd9 49184f6c 137d4f9f 2f392b55 6a9bfe90
    //  checksum                = 0x4aa0fd4e

    assert(index >= 0);

    Integer GI_parent_secret;
    ByteArray_to_GInteger(&parent_secret[0], GI_parent_secret, _33_BYTES);
    Integer GI_curve_order("115792089237316195423570985008687907852837564279074904382605163141518161494337");
    Integer GI_child_secret;

    uint8_t parent_data[_33_BYTES + _4_BYTES];
    parent_data[_33_BYTES + 0] = (reinterpret_cast<uint8_t*>(&index))[3];
    parent_data[_33_BYTES + 1] = (reinterpret_cast<uint8_t*>(&index))[2];
    parent_data[_33_BYTES + 2] = (reinterpret_cast<uint8_t*>(&index))[1];
    parent_data[_33_BYTES + 3] = (reinterpret_cast<uint8_t*>(&index))[0];

    if(hardened) {
        memcpy(&parent_data[0], &parent_secret[0], _33_BYTES);
        parent_data[_33_BYTES + 0] += 0x80;
    }
    else {
        uint8_t parent_pubkey[_COMPRESSED_33_BYTES];
        getPublicKey(parent_secret, _33_BYTES, parent_pubkey, _COMPRESSED_33_BYTES);
        memcpy(&parent_data[0], &parent_pubkey[0], _33_BYTES);
    }

    uint32_t output_size = _64_BYTES;
    char hexResult[2 *output_size + 1];
    uint8_t binResult[output_size];
    
    hmac_sha512(reinterpret_cast<const char*>(parent_chaincode), _32_BYTES,
                parent_data, _33_BYTES + _4_BYTES,
                hexResult, binResult);

    cout << "BIP32 " << index << (hardened ? "'" : "") << " raw (hex): " << hex << hexResult << dec << endl;
    
    ByteArray_to_GInteger(&binResult[0], GI_child_secret, _32_BYTES);
    assert(GI_child_secret > 0 && GI_child_secret < GI_curve_order);

    GI_child_secret += GI_parent_secret;
    GI_child_secret %= GI_curve_order;

    child_secret[0] = 0x00;
    GInteger_to_ByteArray(GI_child_secret, &child_secret[1], _32_BYTES);

    memcpy(child_chaincode, &binResult[32], _32_BYTES);

    getPublicKey(child_secret, _33_BYTES, child_pubkey, _COMPRESSED_33_BYTES);

    cout << "BIP32 " << index << (hardened ? "'" : "") << " chain code (hex): " << hex << b2a_hex(child_chaincode, _32_BYTES) << dec << endl;
    cout << "BIP32 " << index << (hardened ? "'" : "") << " secret (hex): " << hex << b2a_hex(child_secret, _33_BYTES) << dec << endl;
    cout << "BIP32 " << index << (hardened ? "'" : "") << " public key (hex): " << hex << b2a_hex(child_pubkey, _COMPRESSED_33_BYTES) << dec << endl << endl;
}

void find_mnemonic_last_words( const vector<uint16_t> incomplete_word_index_list,
                               vector<uint16_t> &last_word_index_list)
{
    uint8_t full_list_word_count = incomplete_word_index_list.size() + 1;

    assert( full_list_word_count == 12 ||
            full_list_word_count == 15 ||
            full_list_word_count == 18 ||
            full_list_word_count == 21 ||
            full_list_word_count == 24 );

    last_word_index_list.clear();

    uint8_t cs_bit_size = full_list_word_count / 3;

    uint8_t word_bit_entropy = 11;
    uint8_t mnc_byte_entropy = (incomplete_word_index_list.size() * word_bit_entropy + (word_bit_entropy - cs_bit_size)) >> 3;

    vector<uint16_t>::const_iterator mnc_it = incomplete_word_index_list.begin();
    Integer GI_incomplete_word_list_entropy = *mnc_it;
    mnc_it++;
    while( mnc_it != incomplete_word_index_list.end() )
    {
        GI_incomplete_word_list_entropy *= 2048;
        GI_incomplete_word_list_entropy += *mnc_it;
        mnc_it++;
    }

    //cout << hex << GI_incomplete_word_list_entropy << endl;

    uint8_t cs;
    Integer GI_word_list_entropy;
    uint8_t array_to_hash[mnc_byte_entropy];
    uint8_t output_size = _32_BYTES;
    char hexResult[2 *output_size + 1];
    uint8_t binResult[output_size];
    uint8_t sha256_significant_bits = ~(0xFF >> cs_bit_size);
    uint8_t cs_significant_bits = 0xFF >> (8 - cs_bit_size);
    
    uint16_t i;
    uint16_t dictionary_size = Bip39::Dictionary::WordList_english.size();
    for(i=0;i<dictionary_size;i++)
    {       
        GI_word_list_entropy = (GI_incomplete_word_list_entropy << (11 - cs_bit_size)) + (i >> cs_bit_size);

        GInteger_to_ByteArray(GI_word_list_entropy, array_to_hash, mnc_byte_entropy);

        //cout << i << " Entropy candidate =  0x" << hex << b2a_hex(array_to_hash, nbytes_entropy).c_str() << dec << endl;

        sha256(array_to_hash, mnc_byte_entropy, hexResult, binResult);

        //cout << i << " Sha256 =  " << hex << hexResult << dec << endl;

        //cout << i << " Sha256 first byte =  " << hex << b2a_hex(&binResult[0], 1).c_str() << dec << endl;
        //cout << i << " Sha256 significant bits =  " << hex << ((binResult[0] & significant_bits) >> (8 - cs_size)) << dec << endl;

        cs = i & cs_significant_bits;
        //std::bitset<8> x(cs);
        //cout << i << " checksum = " << x << endl;

        if( ((binResult[0] & sha256_significant_bits) >> (8 - cs_bit_size)) == cs )
            last_word_index_list.push_back(i);
    }
}

int power(int x, int y) {
   int i,power=1;
   if(y == 0)
   return 1;
   for(i=1;i<=y;i++)
   power=power*x;
   return power;
}

template <typename T> void mnemonic_from_entropy( const vector<T> entropy, 
                                                  vector<const char*> &mnc )
{  
    assert(sizeof(T)>0);
    assert(entropy.size()>0);

    mnc.clear();

    uint8_t array_to_hash[sizeof(T) * entropy.size()];
    memset(array_to_hash,0,sizeof(array_to_hash));

    for(int i=0;i<entropy.size();i++)
        for(int j=0;j<sizeof(T);j++)
            array_to_hash[i*sizeof(T) + j] = 0xFF & (entropy[i] >> ((sizeof(T) - j - 1) << 3));

    char hexResult[2 *_32_BYTES + 1];
    uint8_t binResult[_32_BYTES];
    sha256(array_to_hash, sizeof(T) * entropy.size(), hexResult, binResult);
    
    //cout << hexResult <<endl;

    Integer GI_entropy; 
    ByteArray_to_GInteger(array_to_hash, GI_entropy, sizeof(array_to_hash));    // entropy
    GI_entropy <<= (sizeof(array_to_hash) >> 2);                                // lshifts to give room for checksum
    GI_entropy += (binResult[0] >> (8 - (sizeof(array_to_hash) >> 2)));         // checksum

    //cout << hex << GI_entropy <<endl;

    uint8_t word_count  = (((sizeof(array_to_hash) << 3) + (sizeof(array_to_hash) >> 2) ) / 11);

    uint16_t index;
    Integer word_mask(0x7FF);
    for(int k=0;k<word_count;k++)
    {
        index = (GI_entropy >> (11 * (word_count - k - 1))) & word_mask;
        mnc.push_back(Bip39::Dictionary::WordList_english.at(index));
    }
}

void find_mnemonic_last_words( const vector<const char*> incomplete_word_list,
                               vector<const char*> &last_word_list)
{
    vector<uint16_t> incomplete_word_index_list;
    vector<uint16_t> last_word_index_list;

    vector<const char*>::const_iterator mnc_it, dic_it;
    for(mnc_it=incomplete_word_list.begin();mnc_it<incomplete_word_list.end();mnc_it++)
    {
        dic_it = find(Bip39::Dictionary::WordList_english.begin(), Bip39::Dictionary::WordList_english.end(), *mnc_it);
        assert(dic_it != Bip39::Dictionary::WordList_english.end());
        uint16_t index = distance(Bip39::Dictionary::WordList_english.begin(), dic_it);
        incomplete_word_index_list.push_back(index);
    }

    find_mnemonic_last_words(incomplete_word_index_list, last_word_index_list);

    last_word_list.clear();

    vector<uint16_t>::const_iterator last_word_index_it;
    for(last_word_index_it=last_word_index_list.begin();last_word_index_it<last_word_index_list.end();last_word_index_it++)
        last_word_list.push_back(Bip39::Dictionary::WordList_english.at(*last_word_index_it));
}

template <typename T> ostream& operator<< (ostream& out, const vector<T>& v) {
    for(auto i: v) out << i;
    return out;
}
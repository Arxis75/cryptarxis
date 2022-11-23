#include "EllipticCurve.h"
#include "bips.h"
#include "bip39_dictionnary.h"

#//include <openssl/evp.h>
//#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <Common.h>
#include <iomanip>
#include <iostream>

using namespace BIP39;

entropy::entropy(size_t bitsize)
    : max_entropy_bitsize(bitsize)
    , current_entropy_bitsize(0)
{
    the_entropy.clear();
}

bool entropy::add_n_bits_of_entropy(const uint32_t extra_e, const uint8_t n_bits)
{
    bool res = false;
    if( (current_entropy_bitsize + n_bits) <= max_entropy_bitsize )
    {
        div_t d = div(current_entropy_bitsize , 32);
        if(!d.rem)
            the_entropy.push_back(extra_e);
        else
        {   uint8_t current_elem_new_bits_count = min(32 - d.rem, (int32_t)n_bits);
            uint8_t next_elem_new_bits_count = max(d.rem + n_bits - 32, 0);
            the_entropy[d.quot] <<= current_elem_new_bits_count;
            the_entropy[d.quot] += (extra_e >> next_elem_new_bits_count);
            if( next_elem_new_bits_count )
                the_entropy.push_back(extra_e & (0xFFFFFFFF >> (32 - next_elem_new_bits_count)));
        }
        current_entropy_bitsize += n_bits;
        res = true;
    }
    return res;
}

bool entropy::get_nth_word(const uint32_t n, const uint8_t word_bitsize, uint32_t& nth_word) const
{
    bool res = false;
    if( word_bitsize <= 32 ) 
    {
        div_t d = div(n * word_bitsize, 32);
        if( d.quot < the_entropy.size() )
        {
            uint8_t nthwbitsize = word_bitsize - max((d.quot << 5) + d.rem + word_bitsize - (int)current_entropy_bitsize, 0);
            int8_t next_elem_new_bits_count = d.rem + nthwbitsize - 32;
            uint32_t nthw = the_entropy[d.quot] & (0xFFFFFFFF >> d.rem);
            if(next_elem_new_bits_count < 0)
                nthw >>= -next_elem_new_bits_count;
            else if(next_elem_new_bits_count > 0)
            {
                nthw <<= next_elem_new_bits_count;
                nthw += the_entropy[d.quot+1] >> (32 - next_elem_new_bits_count);
            }
            nth_word = nthw;
            res = true;
        }
    }
    return res;
}

void entropy::print() const
{
    //TODO: display leading zeroes for each word
    div_t d = div(current_entropy_bitsize , 32);
    int i;
    cout << "0x";
    for(i=0;i<d.quot;i++) 
        cout << hex << the_entropy[i];
    cout << " (" << dec << (d.quot << 5) << " bits)";
    if(d.rem)
        cout << " + 0x" << hex << the_entropy[d.quot] << " (" << dec << d.rem << " bits)";;
    cout << endl;
}

template <typename T> mnemonic::mnemonic(const vector<T>& entropy, const string& pwd)
    : password(pwd)
{
    uint8_t entropy_bitsize = ((sizeof(T) * entropy.size()) << 3);
    uint8_t mnemonic_size = (entropy_bitsize + (entropy_bitsize >> 5)) / 11;

    assert( entropy_bitsize == 128 || entropy_bitsize == 160 || entropy_bitsize == 192
         || entropy_bitsize == 224 || entropy_bitsize == 256 );

    word_index_list.clear();

    v2v_unaligned(entropy, word_index_list, 11 , mnemonic_size-1);

    word_index_list.push_back(find_last_word_index(entropy));
}

mnemonic::mnemonic(const string& words, const string& pwd) 
    : password(pwd)
{
    load_word_index_list(words, word_index_list);

    assert( word_index_list.size() == 12 || word_index_list.size() == 15 || word_index_list.size() == 18 ||
            word_index_list.size() == 21 || word_index_list.size() == 24 );
}

void mnemonic::load_word_index_list(const string& words, vector<uint16_t> list)
{
    string word;
    int32_t index(-1);
    stringstream ssin(words);
    list.clear();

    while( ssin.good() ) {
        ssin >> word;
        std::transform(word.begin(), word.end(), word.begin(), [](unsigned char c){ return tolower(c); });
        int32_t index = getIndex(Dictionary::WordList_english, word);
        if( index >= 0 )
            list.push_back(index);
        word.clear();
    }
}

template <typename T> uint16_t mnemonic::find_last_word_index(const vector<T>& entropy)
{
    uint8_t entropy_bitsize = ((sizeof(T) * entropy.size()) << 3);
    uint8_t checksum_bitsize = (entropy_bitsize >> 5);
    uint8_t array2hash[entropy_bitsize >> 3];
    Vector_to_ByteArray(entropy,array2hash);
    unsigned char digest[32];

    SHA256(array2hash, sizeof(array2hash), digest);
    
    return ((array2hash[sizeof(array2hash)-1] << checksum_bitsize) & 0x7FF) + (digest[0] >> (8 - checksum_bitsize));
}

void mnemonic::list_possible_last_words( const string& incomplete_mnemonic,
                                         vector<const char*> &last_word_list )
{
    vector<uint16_t> incomp_index_list;
    load_word_index_list(incomplete_mnemonic, incomp_index_list);
    uint128_t entropy[(sizeof(incomp_index_list) > 11 ? 2 : 1)];
    memset(entropy,0, sizeof(entropy));

    entropy[0] = incomp_index_list[0];
    for(int i = 1;i<12;i++)
    {
        entropy[0] <<= 11;
        entropy[0] += incomp_index_list[i];
    }

    if(sizeof(incomp_index_list) > 11)
    {
        entropy[0] <<= 7;
        entropy[0]+= ((incomp_index_list[12] & 0b111111100000) >> 4);

        entropy[1] = (incomp_index_list[12] & 0b00000001111);
        entropy[1] <<= 4;

        entropy[1] += incomp_index_list[13];
        for(int i = 1;i<sizeof(incomp_index_list)-11;i++)
        {
            entropy[1] <<= 11;
            entropy[1] += incomp_index_list[13+i];
        }
    }
}

/*void list_possible_last_words( const vector<const char*> incomplete_word_list,
                               vector<const char*> &last_word_list)
{
    vector<uint16_t> incomplete_word_index_list;
    vector<uint16_t> last_word_index_list;

    vector<const char*>::const_iterator mnc_it, dic_it;
    for(mnc_it=incomplete_word_list.begin();mnc_it<incomplete_word_list.end();mnc_it++)
    {
        dic_it = find(Dictionary::WordList_english.begin(), Dictionary::WordList_english.end(), *mnc_it);
        assert(dic_it != Dictionary::WordList_english.end());
        uint16_t index = distance(Dictionary::WordList_english.begin(), dic_it);
        incomplete_word_index_list.push_back(index);
    }

    find_mnemonic_last_words(incomplete_word_index_list, last_word_index_list);

    last_word_list.clear();

    vector<uint16_t>::const_iterator last_word_index_it;
    for(last_word_index_it=last_word_index_list.begin();last_word_index_it<last_word_index_list.end();last_word_index_it++)
        last_word_list.push_back(Bip39::Dictionary::WordList_english.at(*last_word_index_it));
}*/

void mnemonic::print(bool as_index_in_dictionnary) {
    for(uint32_t i=0;i<word_index_list.size();i++) {
        if(as_index_in_dictionnary)
            cout << word_index_list[i];
        else
            cout << Dictionary::WordList_english.at(word_index_list[i]);
        cout << " ";
    }
    cout << endl;
}
/*
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
}*/

template mnemonic::mnemonic(const vector<uint8_t>&, const string& pwd);    //for the linker
template mnemonic::mnemonic(const vector<uint16_t>&, const string& pwd);   //for the linker
template mnemonic::mnemonic(const vector<uint32_t>&, const string& pwd);   //for the linker
template mnemonic::mnemonic(const vector<uint64_t>&, const string& pwd);   //for the linker
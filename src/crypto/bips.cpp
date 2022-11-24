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

entropy::entropy()
    : current_bitsize(0)
{
    the_entropy.clear();
}

void entropy::add_n_bits_of_entropy(const uint32_t extra_e, const uint8_t n_bits)
{
    div_t d = div(current_bitsize , 32);
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
    current_bitsize += n_bits;
}

void entropy::clear()
{
    the_entropy.clear();
    current_bitsize = 0;
}

bool entropy::get_nth_word(const uint8_t n, const uint8_t word_bitsize, uint32_t& nth_word) const
{
    bool res = false;
    if( word_bitsize <= 32 ) 
    {
        div_t index = div(n * word_bitsize, 32);
        if( index.quot < the_entropy.size() )
        {
            uint8_t tail_padding = max(((index.quot+1) << 5) - current_bitsize, 0); //the_entropy last element size might be < 32 bits
            uint8_t nthwbitsize = word_bitsize - max((index.quot << 5) + index.rem + word_bitsize - (int)current_bitsize, 0);
            int8_t next_elem_new_bits_count = index.rem + nthwbitsize - (32 - tail_padding);
            uint32_t nthw = the_entropy[index.quot] & (0xFFFFFFFF >> (index.rem + tail_padding));
            if(next_elem_new_bits_count < 0)
                nthw >>= -next_elem_new_bits_count;
            else if(next_elem_new_bits_count > 0)
            {
                tail_padding = max(((index.quot+2) << 5) - current_bitsize, 0);
                nthw <<= next_elem_new_bits_count;
                nthw += the_entropy[index.quot+1] >> ((32 - tail_padding) - next_elem_new_bits_count);
            }
            nth_word = nthw;
            res = true;
        }
    }
    return res;
}

uint8_t entropy::checksum(const uint8_t checksum_bitsize) const
{
    assert(current_bitsize % 32 == 0);
    uint8_t array2hash[current_bitsize >> 3];
    Vector_to_ByteArray(the_entropy,array2hash);
    unsigned char digest[32];
    SHA256(array2hash, sizeof(array2hash), digest);                    
    return digest[0] >> (8 - checksum_bitsize);
}

void entropy::print() const
{
    //TODO: display leading zeroes for each word
    div_t d = div(current_bitsize , 32);
    int i;
    cout << "0x";
    for(i=0;i<d.quot;i++) 
        cout << hex << the_entropy[i];
    cout << " (" << dec << (d.quot << 5) << " bits)";
    if(d.rem)
        cout << " + 0x" << hex << the_entropy[d.quot] << " (" << dec << d.rem << " bits)";;
    cout << endl;
}

mnemonic::mnemonic(const size_t entropy_bitsize, const vector<string>* dictionnary)
{   
    div_t d;
    dic = (dictionnary ? dictionnary : &BIP39::Dictionary::WordList_english);
    assert(dic->size() > 1);     // at least 2 elements
    //TOD: verify each element of the dictionnary is unique

    went = log2(dic->size());
    assert(went<=32);           // max word entropy = 32 bits

    ent = entropy_bitsize;
    assert(ent >= 128);         // for security
    d = div(ent, 32);
    assert(!d.rem);             // multiple of 32

    d = div(ent, (int)went);
    ms = d.quot + 1;            // 1 extra word for checksum/alignment
    cs = went - d.rem;
}

bool mnemonic::add_word(const string word)
{
    bool res = false;
    if( e.getCurrentBitSize() < ent )
    {
        bool is_last_word = (e.getCurrentBitSize() + went > ent);
        uint32_t controlled_went = went;
        if( is_last_word )
            controlled_went -= cs;
        vector<string>::const_iterator dic_it;
        dic_it = find(dic->begin(), dic->end(), word);
        if( dic_it != dic->end() )
        {
            uint32_t index = distance(dic->begin(), dic_it);
            entropy tmp_e(e);
            tmp_e.add_n_bits_of_entropy(index >> (went - controlled_went), controlled_went);
            if( !is_last_word || tmp_e.checksum(cs) == (index & (0xFF >> (8 - cs))) )
            {
                e = tmp_e;
                if(is_last_word) last_word = word;
                res = true;
            }
        }
    }
    if(!res) cout << "invalid word!" << endl;
    return res;
}

void mnemonic::clear()
{
    last_word.clear();
    e.clear();
}

void mnemonic::print(bool as_index_list) const
{
    if( as_index_list )
        e.print();
    else
    {
        uint32_t nth_word;
        for(int i=0;i<(e.getCurrentBitSize()/went);i++)
        {
            if( e.get_nth_word(i,went,nth_word) )
                cout << dic->at(nth_word) << " ";
        }
        if(last_word != "") cout << last_word;
        cout << endl;
    }
}

bool mnemonic::list_possible_last_word(vector<string>& list)
{
    bool res = false;
    if( e.getCurrentBitSize() == went * (ms-1) )
    {
        list.clear();
        for(int i=0;i<(1<<(went-cs));i++)
        {
            entropy tmp(e);
            tmp.add_n_bits_of_entropy(i, went-cs);
            list.push_back(dic->at((i << cs) + tmp.checksum(cs)));
        }
        res = true;
    }
    return res;
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

//template mnemonic::mnemonic(const vector<uint8_t>&, const string& pwd);    //for the linker
//template mnemonic::mnemonic(const vector<uint16_t>&, const string& pwd);   //for the linker
//template mnemonic::mnemonic(const vector<uint32_t>&, const string& pwd);   //for the linker
//template mnemonic::mnemonic(const vector<uint64_t>&, const string& pwd);   //for the linker
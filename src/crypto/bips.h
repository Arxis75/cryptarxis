#pragma once

#include <openssl/sha.h>

#include <Common.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <bitset>

using namespace std;

namespace BIP39 {

class entropy
{
    public:
        entropy(size_t bitsize)
            : max_entropy_bitsize(bitsize)
            , current_entropy_bitsize(0)
        {
            the_entropy.clear();
        }

        bool add_n_bits_of_entropy(uint32_t extra_e, uint8_t n_bits)
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
        
        bool get_nth_word(const uint32_t n, const uint8_t word_bitsize, uint32_t& nth_word) const
        {
            bool res = false;
            div_t d = div(n * word_bitsize, 32);
            if( d.quot < the_entropy.size() )
            {
                uint8_t nthwbitsize = word_bitsize - max((d.quot << 5) + d.rem + word_bitsize - current_entropy_bitsize, 0);
                int8_t next_elem_new_bits_count = d.rem + nthwbitsize - 32;
                uint32_t nthw = the_entropy[d.quot] & (0xFFFFFFFF >> d.rem);
                if(next_elem_new_bits_count <= 0)
                {
                    nthw >>= -next_elem_new_bits_count;
                    nth_word = nthw;
                    res = true;
                }
                else
                {
                    nthw <<= next_elem_new_bits_count;
                    nthw += the_entropy[d.quot+1] >> (32 - next_elem_new_bits_count);
                    nth_word = nthw;
                    res = true;
                }
            }
            return res;
        }

        void print() const
        {
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

    /*bool add_last_word_entropy(uint8_t e)
    {
        bool res = false;
        uint8_t main_entropy_bit_size = main_entropy.size() * 11;
        if( main_entropy_bit_size == 121
            || main_entropy_bit_size == 154
            || main_entropy_bit_size == 187
            || main_entropy_bit_size == 220
            || main_entropy_bit_size == 253 )
        {
            uint8_t checksum_bit_size = main_entropy_bit_size >> 5;
            if( e == (e & (0x7FF >> checksum_bit_size)) )
            {
                last_word_entropy = e;
                res = true;
            }
        }
        return res;
    }*/

    private:
        size_t max_entropy_bitsize;
        size_t current_entropy_bitsize;
        vector<uint32_t> the_entropy;
};

class mnemonic
{
    public:
        mnemonic(const string& words, const string& pwd = "");
        template <typename T> mnemonic(const vector<T>& entropy, const string& pwd = "");
        
        void list_possible_last_words( const string& incomplete_word_list,
                                       vector<const char*> &last_word_list );
        
        void print(bool as_index_in_dictionnary = false);
    
    protected:
        void load_word_index_list(const string& words, vector<uint16_t> list);
        template <typename T> uint16_t find_last_word_index(const vector<T>& entropy);
    
    private:
        vector<uint16_t> word_index_list;
        string password;
};
}

class seed
{
    public:
        seed(vector<uint8_t> s);
    
    private:

};

/*
namespace BIP32 {
class pubkey
{
    public:
        pubkey(x,y);
        pubkey(px);
        pubkey(pxy);
        pubkey(xy);
    
    protected:
        bool is_valid();

    private:
        Integer X, Y;
        vector<uint8_t> prefixed_x_y;
};

class secret
{
        public:
        secret::secret(s);
        secret::secret(prefixed_s);
    
    protected:
        bool is_valid();

    private:
        Integer ;
        uint8_t prefix;       
};

class Factory{ 
    public:
        static Bip32* getInstance()
        {
            if (instancePtr == NULL) {
                instancePtr = new Bip32();
                return instancePtr;
            }
            else
                return instancePtr;
        }

        // deleting copy constructor
        Bip32(const Bip32& obj) = delete;

        bip39_seed* derive_seed(const bip39_mnemonic& mnc);

        bip32_secret* derive_m_child(const bip32_seed& seed); 
        bip32_secret* derive_child(const bip32_secret& parent_secret, uint32_t child_index, bool hardened);
        bip32_pubkey* derive_child(const bip32_pubkey& parent_pubkey, uint32_t child_index);    //secret remains unknown

    private:
        // Default constructor
        Bip32() {}

    public:

    private:
        static Bip32* instancePtr;
};

// initializing instancePtr with NULL
Factory* Factory::instancePtr = NULL;
}

namespace BIP44
{

}*/
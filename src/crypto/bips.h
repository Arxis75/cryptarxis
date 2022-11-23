#pragma once

#include <openssl/sha.h>

//#include <Common.h>
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
        entropy(size_t bitsize);

        bool add_n_bits_of_entropy(uint32_t extra_e, uint8_t n_bits);
        bool get_nth_word(const uint32_t n, const uint8_t word_bitsize, uint32_t& nth_word) const;
        void print() const;

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
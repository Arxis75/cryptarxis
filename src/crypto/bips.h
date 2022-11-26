#pragma once

#include <openssl/sha.h>

#include "bip39_dictionnary.h"

using namespace std;

namespace BIP39 {

class entropy
{
    public:
        entropy();

        void clear();
        void add_n_bits_of_entropy(const uint32_t extra_e, const uint8_t n_bits);

        bool get_nth_word(const uint8_t n, const uint8_t word_bitsize, uint32_t& nth_word) const;
        uint16_t getCurrentBitSize() const { return current_bitsize; };
        uint8_t checksum(const uint8_t checksum_bitsize) const;
        void print() const;

    private:
        uint16_t current_bitsize;
        vector<uint32_t> the_entropy;
};

class mnemonic
{
    public:
        mnemonic(const size_t entropy_bitsize, const vector<string>* dictionnary = 0);

        void clear();
        bool add_word(const string& word);
        bool set_full_word_list(const string& list);
        bool generate_seed(const string& pwd) {}
      
        bool is_valid() const;
        bool list_possible_last_word(vector<string>& list) const;
        const string get_word_list() const;
        const string get_last_word() const;
        void print(bool as_index_list = false) const;

private:
        entropy e;
        const vector<string>* dic;
        uint8_t went;
        uint16_t ent;
        uint8_t ms;
        uint8_t cs;
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
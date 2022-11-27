#pragma once

#include "EllipticCurve.h"

using namespace std;
using namespace Givaro;

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

namespace BIP32 {

class extpubkey: public Point
{
    public:
        extpubkey(Secp256k1& curve, Integer k, Integer cc);

        const Integer getKey(size_t size) const;
        const Integer getChainCode() const { return chaincode; }
        Integer getAddress() const;

    private:
        Point key;
        Integer chaincode;
        Integer the_address;
};

class seed
{
    public:
        seed(const BIP39::mnemonic& mnc, const string& pwd);

        const uint8_t* get() const { return the_seed; }
        void print() const;

    private:
        uint8_t the_seed[64];
};

class extprivkey
{
    public:
        extprivkey(const seed& s);
        extprivkey(const extprivkey& parent_secret, const int32_t index, const bool hardened);
        const Integer getSecret() const { return secret; }
        const extpubkey& getExtPubKey() const { return *pubkey; }
        extprivkey* derive(int32_t child_index, bool child_is_hardened);

    private:
        Integer secret;
        extpubkey* pubkey;
        extprivkey* child;
};
}
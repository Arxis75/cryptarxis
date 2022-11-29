#pragma once

#include "EllipticCurve.h"
#include <Common.h>

using namespace std;
using namespace Givaro;

namespace BIP39 {

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
        const bitstream get_seed(const string& pwd) const;
        void print(bool as_index_list = false) const;

private:
        bitstream entropy;
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
        extpubkey(Secp256k1& curve, const bitstream& k, const bitstream& cc);

        const bitstream& getChainCode() const { return chaincode; }
        const bitstream getKey(size_t size) const;
        const bitstream getAddress() const;

    private:
        Point key;
        bitstream chaincode;
};

class extprivkey
{
    public:
        extprivkey(const bitstream& s);
        extprivkey(const extprivkey& parent_secret, const int32_t index, const bool hardened);
        ~extprivkey() { if(pubkey) delete pubkey; }

        const bitstream& getSecret() const { return secret; }
        const bitstream& getChainCode() const { return pubkey->getChainCode(); }
        const extpubkey& getExtPubKey() const { return *pubkey; }

    private:
        bitstream secret;
        extpubkey* pubkey;
};
}
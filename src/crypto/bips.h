#pragma once

#include "EllipticCurve.h"
#include <Common.h>

using namespace std;
using namespace Givaro;

namespace BIP39 {

class Mnemonic
{
    public:
        Mnemonic(const size_t entropy_bitsize, const vector<string>* dictionnary = 0);

        void clear();
        bool add_word(const string& word);
        bool add_entropy(const string& entropy, const uint32_t bitsize, const uint8_t in_base);
        bool set_full_word_list(const string& list);
        const uint16_t getEntropySize() const { return _ent; }

        bool is_valid() const;
        bool list_possible_last_word(vector<string>& list) const;
        const string get_word_list() const;
        const string get_last_word() const;
        const Bitstream get_seed(const string& pwd) const;
        void print(bool as_index_list = false) const;

private:
        Bitstream _entropy;
        const vector<string>* _dic;
        uint8_t _went;
        uint16_t _ent;
        uint8_t _ms;
        uint8_t _cs;
};
}

class Pubkey
{
    public:
        enum class Format{PREFIXED_X, XY, PREFIXED_XY};
        
        Pubkey(const Pubkey& key); 
        Pubkey(const Point& p = Point(), const EllipticCurve& curve = Secp256k1::GetInstance());
        Pubkey(const Point& p, const Bitstream& cc, const EllipticCurve& curve = Secp256k1::GetInstance());

        const Point& getPoint() const { return _point; }
        const EllipticCurve& getCurve() const { return _ecc; }
        const Bitstream getKey(Format f) const;
        const Bitstream getAddress() const;

        uint32_t getFormatBitSize(Pubkey::Format f) const;

        const Bitstream& getChainCode() const { return _chaincode; }

    private:
        EllipticCurve _ecc;
        Point _point;
        Bitstream _chaincode;   //BIP32
};

class Privkey
{
    public:
        Privkey(const Integer& k, const EllipticCurve& curve = Secp256k1::GetInstance());
        Privkey(const Bitstream& seed, const EllipticCurve& curve = Secp256k1::GetInstance());
        Privkey(const Privkey& parent_extprivkey, const int32_t index, const bool hardened);

        const EllipticCurve& getCurve() const { return _pubkey.getCurve(); }
        const Bitstream& getChainCode() const { return _pubkey.getChainCode(); }
        const Pubkey& getPubKey() const { return _pubkey; }

        const Bitstream& getSecret() const { return _secret; }
        operator const Integer() const { return Integer(_secret); }

    private:
        Pubkey _pubkey;
        Bitstream _secret;
};

class Signature: public EllipticCurve
{
    public:
        Signature(const Integer& r, const Integer& s, const bool parity, const EllipticCurve& curve);
        
        bool isValid(const Bitstream& h, const Bitstream& address) const;
        bool ecrecover(Pubkey& key, const Bitstream& h, const Bitstream& from_address = Bitstream()) const;

    private:
        Integer _r;
        Integer _s;
        bool _parity;
};

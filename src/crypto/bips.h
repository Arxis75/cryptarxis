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
        const uint16_t getEntropySize() const { return m_ent; }

        bool is_valid() const;
        bool list_possible_last_word(vector<string>& list) const;
        const string get_word_list() const;
        const string get_last_word() const;
        const Bitstream get_seed(const string& pwd) const;
        void print(bool as_index_list = false) const;

private:
        Bitstream m_entropy;
        const vector<string>* m_dic;
        uint8_t m_went;
        uint16_t m_ent;
        uint8_t m_ms;
        uint8_t m_cs;
};
}

class Pubkey
{
    public:
        enum class Format{PREFIXED_X, XY, PREFIXED_XY};
        
        Pubkey(const Pubkey& key); 
        Pubkey(const Point& p = Point(), const EllipticCurve& curve = Secp256k1::GetInstance());
        Pubkey(const Point& p, const Bitstream& cc, const EllipticCurve& curve = Secp256k1::GetInstance());

        const Point& getPoint() const { return m_point; }
        const EllipticCurve& getCurve() const { return m_ecc; }
        const Bitstream getKey(Format f) const;
        const Bitstream getAddress() const;

        uint32_t getFormatBitSize(Pubkey::Format f) const;

        const Bitstream& getChainCode() const { return m_chaincode; }

        inline bool operator==(const Pubkey& k) const { return m_ecc == k.getCurve() && m_point == k.getPoint() && m_chaincode == k.getChainCode(); }

    private:
        EllipticCurve m_ecc;
        Point m_point;
        Bitstream m_chaincode;   //BIP32
};

class Signature: public EllipticCurve
{
    public:
        Signature(const Integer& r, const Integer& s, const bool imparity, const EllipticCurve& curve = Secp256k1::GetInstance());

        void fixMalleability();
        bool isMalleabilityFixed() const { return m_s <= m_smax; }

        bool isValid(const Bitstream& h, const Bitstream& address, const bool enforce_eip2 = true) const;
        bool ecrecover(Pubkey& key, const Bitstream& h, const Bitstream& from_address = Bitstream()) const;

        const Integer& get_r() const { return m_r; }
        const Integer& get_s() const { return m_s; }
        const bool get_imparity() const { return m_imparity; }

        inline bool operator==(const Signature& s) const { return m_r == s.get_r() && m_s == s.get_s() && m_imparity == s.get_imparity(); }

    private:
        Integer m_r;
        Integer m_s;
        Integer m_smax; //EIP-2: fixes signature malleability
        bool m_imparity;
};

class Privkey
{
    public:
        enum class Format{SCALAR, SEED};

        //Privkey(const Integer& k, const EllipticCurve& curve = Secp256k1::GetInstance());
        Privkey(const Bitstream& seed, const Format f = Format::SCALAR, const EllipticCurve& curve = Secp256k1::GetInstance());
        Privkey(const Privkey& parent_extprivkey, const int32_t index, const bool hardened);

        const EllipticCurve& getCurve() const { return m_pubkey.getCurve(); }
        const Bitstream& getChainCode() const { return m_pubkey.getChainCode(); }
        const Pubkey& getPubKey() const { return m_pubkey; }

        const Bitstream& getSecret() const { return m_secret; }
        operator const Integer() const { return Integer(m_secret); }

        Signature sign(const Bitstream& h, const bool enforce_eip2 = true) const;

        inline bool operator==(const Privkey& k) const { return m_secret == k.getSecret(); }

    private:
        Pubkey m_pubkey;
        Bitstream m_secret;
};

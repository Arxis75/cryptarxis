#include <Common.h>
#include <algorithm>

#include "EllipticCurve.h"
#include "bips.h"
#include "bip39_dictionnary.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <ethash/keccak.hpp>

using namespace BIP39;
using namespace ethash;

//----------------------------------------------------------- BIP32 -----------------------------------------------------------------

Pubkey::Pubkey(const Point& p, const EllipticCurve& curve)
    : m_ecc(curve)
    , m_point(p)
{ }

Pubkey::Pubkey(const Point& p, const Bitstream& cc, const EllipticCurve& curve)
    : m_ecc(curve)
    , m_point(p)
    , m_chaincode(cc)
{ }

Pubkey::Pubkey(const Pubkey& key) 
    : m_ecc(key.m_ecc)
    , m_point(key.m_point)
{ }

const Bitstream Pubkey::getKey(Format f) const
{   
    uint32_t ecc_order_bsize = m_ecc.getGeneratorOrder().size_in_base(2);
    uint32_t bsize;
    Integer prefix = 0;
    if( f == Format::PREFIXED_X )
    {
        prefix = ((m_point.getY() % 2) ? 0x03 : 0x02);
        bsize = ecc_order_bsize + 8;
    }
    else if( f == Format::PREFIXED_XY )
    {
        prefix = 0x04;
        bsize = ecc_order_bsize + 8;
    }
    else
        bsize = ecc_order_bsize;     // Ethereum default: f == Format::XY

    Integer publicKey = (prefix << ecc_order_bsize);
    //cout << hex << publicKey << endl;
    publicKey += m_point.getX();
    //cout << hex << publicKey << endl;
    
    if( f == Format::PREFIXED_XY || f == Format::XY )
    {
        publicKey <<= ecc_order_bsize;
        publicKey += m_point.getY();
        bsize += ecc_order_bsize;
    }
    //cout << hex << publicKey << endl;
    //cout << dec << bsize << endl;
    return Bitstream(publicKey, bsize);
}

uint32_t Pubkey::getFormatBitSize(Format f) const
{
    switch(f)
    {
        case Format::PREFIXED_X:
            return m_ecc.getGeneratorOrder().size_in_base(2) + 8;
        case Format::PREFIXED_XY:
            return (m_ecc.getGeneratorOrder().size_in_base(2)<<1) + 8;
        default:
            return (m_ecc.getGeneratorOrder().size_in_base(2)<<1);
    }
}

const Bitstream Pubkey::getAddress() const
{
    hash256 h = keccak256(getKey(Format::XY), getFormatBitSize(Format::XY)>>3);
    return Bitstream(&h.bytes[32 - 20], 160);
}

Signature::Signature(const Integer& r, const Integer& s, const bool imparity, const EllipticCurve& curve)
    : EllipticCurve(curve)
    , m_r(r)
    , m_s(s)
    , m_smax(curve.getGeneratorOrder()>>1)   //Cf EIP-2
    , m_imparity(imparity)
{ }

void Signature::fixMalleability()
{
    if(!isMalleabilityFixed())
    {
        m_s = getGeneratorOrder() - m_s;
        m_imparity = !m_imparity;
    }
}

bool Signature::isValid(const Bitstream& h, const Bitstream& from_address, const bool enforce_eip2) const
{
    Pubkey key;
    return ( from_address.bitsize() == 160 &&
             (m_s <= m_smax || !enforce_eip2) &&
             ecrecover(key, h, from_address) && from_address == key.getAddress() );
}

bool Signature::ecrecover(Pubkey& key, const Bitstream& h, const Bitstream& from_address) const
{
    bool ret = false;
    Point Q_candidate;
    if( recover(Q_candidate, h, m_r, m_s, m_imparity, false) )
    {
        ret = true;
        key = Pubkey(Q_candidate, (*this));
        //cout << hex << "Q_candidate adresse = 0x" << key.getAddress() << endl;
        if( from_address.bitsize() == 160 && key.getAddress() != from_address )
        {
            ret = false;
            if( recover(Q_candidate, h, m_r, m_s, m_imparity, true) )
            {
                key = Pubkey(Q_candidate, (*this));
                ret = (key.getAddress() == from_address);
            }
        }
    }
    return ret;
}

Privkey::Privkey(const Privkey& parent_privkey, const int32_t index, const bool hardened)
{
    assert(index >= 0);

    Bitstream parent_data;
    Bitstream parent_cc(parent_privkey.getChainCode());
    uint32_t suffix = index;
    if(!hardened)
        parent_data = parent_privkey.getPubKey().getKey(Pubkey::Format::PREFIXED_X);
    else
    {
        parent_data.set(0x00, 8);
        parent_data.push_back(parent_privkey.getSecret(),256);
        suffix += 0x80000000;
    }      
    parent_data.push_back(suffix, 32);
   
    Bitstream digest(Integer(0), 512);
    uint32_t dilen;
    unsigned char *res = HMAC( EVP_sha512(),
                               parent_cc, 32,
                               parent_data, 33 + 4,
                               digest, &dilen);
    if (res && dilen == 64)
    {
        cout << "BIP32 " << dec << index << (hardened ? "'" : "") << " raw (hex): " << digest << dec << endl;
    
        EllipticCurve curve = parent_privkey.getCurve();
        Integer n = curve.getGeneratorOrder();
        Integer s = a2Integer(&digest[0], 256); // first 256bits/512 = secret
        s += parent_privkey.getSecret();
        s %= n;
        const_cast<Bitstream&>(m_secret).set(s, n.size_in_base(2));

        Bitstream cc(&digest[32], 256);
        m_pubkey = Pubkey(curve.p_scalar(curve.getGenerator(), m_secret), cc, curve);

        cout << "BIP32 " << index << (hardened ? "'" : "") << " chain code (hex): " << hex << m_pubkey.getChainCode() << dec << endl;
        cout << "BIP32 " << index << (hardened ? "'" : "") << " secret (hex): " << hex << m_secret << dec << endl;
        cout << "BIP32 " << index << (hardened ? "'" : "") << " public key (hex): " << hex << m_pubkey.getKey(Pubkey::Format::PREFIXED_X) << dec << endl << endl;
    }
}

Privkey::Privkey(const Bitstream& value, const Format f, const EllipticCurve& curve)
{
    if(f == Format::SCALAR)
    {
        assert(Integer(value) > 0 && Integer(value) < curve.getGeneratorOrder());
        
        m_secret = value;
        m_pubkey = Pubkey(curve.p_scalar(curve.getGenerator(), m_secret), curve);
    }
    else
    {   
        assert(value.bitsize() >= 128 && value.bitsize() <= 512);

        // Cf https://www.openssl.org/docs/manmaster/man3/HMAC.html
        // Cf https://www.openssl.org/docs/manmaster/man3/EVP_sha512.html

        Bitstream digest(Integer(0), 512);
        uint32_t dilen;

        unsigned char *res = HMAC( EVP_sha512(),
                                "Bitcoin seed", 12,
                                value, (value.bitsize()>>3),
                                digest, &dilen);
        if (res && dilen == 64)
        {
            cout << "BIP32 Root raw (hex): " << digest << dec << endl;

            Integer n = curve.getGeneratorOrder();
            Integer s = a2Integer(&digest[0], 256); // first 256bits/512 = secret
            s %= curve.getGeneratorOrder();
            const_cast<Bitstream&>(m_secret).set(s, n.size_in_base(2));

            Bitstream cc(&digest[32], 256);
            m_pubkey = Pubkey(curve.p_scalar(curve.getGenerator(), m_secret), cc, curve);

            cout << "BIP32 " << "Root chain code (hex): " << hex << m_pubkey.getChainCode() << dec << endl;
            cout << "BIP32 " << "Root secret (hex): " << hex << m_secret << dec << endl;
            cout << "BIP32 " << "Root public key (hex): " << hex << m_pubkey.getKey(Pubkey::Format::PREFIXED_X) << dec << endl << endl;
        }
    }
}

Signature Privkey::sign(const Bitstream& h, const bool enforce_eip2) const
{
    EllipticCurve ecc = m_pubkey.getCurve();
    Integer n = ecc.getGeneratorOrder();

    Integer k_1;
    bool imparity;
    Integer r;
    uint8_t nonce_to_skip = 0;
    while(true)
    {
        Integer k = ecc.generate_RFC6979_nonce(m_secret, h, nonce_to_skip);
        //cout << hex << "k = 0x" << k << endl;
        inv(k_1, k, n);
        //cout << hex << "k^(-1) = 0x" << k_1 << endl;
        Point R = ecc.p_scalar(ecc.getGenerator(), k);
        //cout << hex << "R = (0x" << R.getX() << ", 0x" << R.getY() << ")" << endl;
        imparity = isOdd(R.getY());
        //cout << "R.y imparity = " << (imparity ? "odd (0x01)" : "even (0x00)") << endl;
        r = R.getX();
        //cout << hex << "r = 0x" << r << endl;
        if(r>0 && r<n) break;
        nonce_to_skip++;
    }
    Integer s = (k_1 * (Integer(h) + (r*m_secret))) % n;
    //cout << hex << "s = k^(-1) . (h + r.x) = 0x" << s << endl;

    Signature sig(r, s, imparity, ecc);
    if(enforce_eip2)
        sig.fixMalleability();

    return sig;
}

//----------------------------------------------------------- BIP39 -----------------------------------------------------------------

Mnemonic::Mnemonic(const size_t entropy_bitsize, const vector<string> *dictionnary)
{
    div_t d;
    m_dic = (dictionnary ? dictionnary : &BIP39::Dictionary::WordList_english);
    assert(m_dic->size() > 1); // at least 2 elements
    // TOD: verify each element of the dictionnary is unique

    m_went = log2(m_dic->size());
    assert(m_went <= 32); // max word entropy = 32 bits

    m_ent = entropy_bitsize;
    assert(m_ent >= 128); // for security
    d = div(m_ent, 32);
    assert(!d.rem); // multiple of 32

    d = div(m_ent, m_went);
    m_ms = d.quot + 1; // 1 extra word for checksum/alignment
    m_cs = m_went - d.rem;
}

bool Mnemonic::add_entropy(const string& entropy, const uint32_t bitsize, const uint8_t in_base)
{
    bool ret = false;
    if( m_entropy.bitsize() + bitsize <= m_ent)
    {
        m_entropy.push_back(entropy, bitsize, in_base);
        ret = true;
    }
    return ret;
}

bool Mnemonic::add_word(const string &word)
{
    bool res = false;
    std::string data = word;
    std::transform(data.begin(), data.end(), data.begin(), ::tolower);
    vector<string>::const_iterator dic_it;
    dic_it = find(m_dic->begin(), m_dic->end(), data);
    if (dic_it != m_dic->end() && m_entropy.bitsize() < m_ent)
    {
        bool is_last_word = (m_entropy.bitsize() + m_went > m_ent);
        uint32_t controlled_went = m_went;
        if (is_last_word)
            controlled_went -= m_cs;
        uint32_t index = distance(m_dic->begin(), dic_it);
        Bitstream e(m_entropy);
        e.push_back(index >> (m_went - controlled_went), controlled_went);
        if (!is_last_word || e.sha256().at(0,m_cs).as_uint8() == (index & (0xFF >> (8 - m_cs))))
        {
            m_entropy = e;
            res = true;
        }
    }
    if (!res)
        cout << "invalid word addition!" << endl;
    return res;
}

bool Mnemonic::set_full_word_list(const string &list)
{
    bool res = false;
    clear();
    vector<string> v = split(list, " ");
    if (v.size() == m_ms)
        for (int i = 0; i < v.size(); i++)
        {
            res = add_word(v[i]);
            if (!res)
            {
                clear();
                break;
            }
        }
    return res;
}

bool Mnemonic::is_valid() const
{
    return (m_entropy.bitsize() == m_ent);
}

void Mnemonic::clear()
{
    m_entropy.clear();
}

const string Mnemonic::get_word_list() const
{
    string ret("");
    uint32_t nth_word;
    div_t d = div(m_entropy.bitsize(), m_went);
    for (int i = 0; i < d.quot; i++)
    {
        if(ret.size() > 0)
            ret += " ";
        ret += m_dic->at(m_entropy.at(i*m_went,m_went).as_uint16());
    }
    if (d.rem && is_valid())
        ret += " " + get_last_word();
    return ret;
}

bool Mnemonic::list_possible_last_word(vector<string> &list) const
{
    bool res = false;
    if (m_entropy.bitsize() == m_went * (m_ms - 1))
    {
        list.clear();
        for (int i = 0; i < (1 << (m_went - m_cs)); i++)
        {
            Bitstream tmp(m_entropy);
            tmp.push_back(i, m_went - m_cs);
            list.push_back(m_dic->at((i << m_cs) + tmp.sha256().at(0,m_cs).as_uint8()));
        }
        res = true;
    }
    return res;
}

const string Mnemonic::get_last_word() const
{
    string ret("");
    if (is_valid())
    {
        Integer index = (m_entropy.at((m_ms - 1)*m_went, m_went-m_cs).as_uint8() << m_cs) + m_entropy.sha256().at(0,m_cs).as_uint8();
        ret = m_dic->at(index);
    }
    return ret;
}

void Mnemonic::print(bool as_index_list) const
{
    if (as_index_list)
        cout << m_entropy << endl;
    else
        cout << get_word_list() << endl;
}

const Bitstream Mnemonic::get_seed(const string& pwd) const
{
    Bitstream the_seed(Integer(0), 512);
    if (is_valid())
    {
        const string pass = get_word_list();
        char salt[8 + pwd.size()];
        strcpy(salt, "mnemonic");
        strcat(salt, pwd.c_str()); // salt = "mnemonic" + password

        // Cf https://www.openssl.org/docs/manmaster/man3/PKCS5_PBKDF2_HMAC.html

        PKCS5_PBKDF2_HMAC( pass.c_str(), pass.size(),
                           reinterpret_cast<const unsigned char *>(salt), strlen(reinterpret_cast<const char *>(salt)),
                           2048,
                           EVP_sha512(),
                           64,
                           the_seed );

        cout << "BIP32 password : " << pwd.c_str() << endl;
        cout << "BIP32 seed (hex): " << the_seed << dec << endl;
    }
    return the_seed;
}
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
    : _ecc(curve)
    , _point(p)
{ }

Pubkey::Pubkey(const Point& p, const Bitstream& cc, const EllipticCurve& curve)
    : _ecc(curve)
    , _point(p)
    , _chaincode(cc)
{ }

Pubkey::Pubkey(const Pubkey& key) 
    : _ecc(key._ecc)
    , _point(key._point)
    , _chaincode(key._chaincode)
{ }

const Bitstream Pubkey::getKey(Format f) const
{   
    uint32_t ecc_order_bsize = _ecc.getCurveOrder().size_in_base(2);
    uint32_t bsize;
    Integer prefix = 0;
    if( f == Format::PREFIXED_X )
    {
        prefix = ((_point.getY() % 2) ? 0x03 : 0x02);
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
    publicKey += _point.getX();
    //cout << hex << publicKey << endl;
    
    if( f == Format::PREFIXED_XY || f == Format::XY )
    {
        publicKey <<= ecc_order_bsize;
        publicKey += _point.getY();
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
            return _ecc.getCurveOrder().size_in_base(2) + 8;
        case Format::PREFIXED_XY:
            return (_ecc.getCurveOrder().size_in_base(2)<<1) + 8;
        default:
            return (_ecc.getCurveOrder().size_in_base(2)<<1);
    }
}

const Bitstream Pubkey::getAddress() const
{
    hash256 h = keccak256(getKey(Format::XY), getFormatBitSize(Format::XY)>>3);
    return Bitstream(&h.bytes[32 - 20], 160);
}

Signature::Signature(const Integer& r, const Integer& s, const bool parity, const EllipticCurve& curve)
    : EllipticCurve(curve)
    , _r(r)
    , _s(s)
    , _parity(parity)
{ }

bool Signature::isValid(const Bitstream& h, const Bitstream& from_address) const
{
    Pubkey key;
    return ( from_address.bitsize() == 160 && ecrecover(key, h, from_address) && from_address == key.getAddress() );
}

bool Signature::ecrecover(Pubkey& key, const Bitstream& h, const Bitstream& from_address) const
{
    bool ret = false;
    Point Q_candidate;
    if( recover(Q_candidate, h, _r, _s, _parity, false) )
    {
        ret = true;
        key = Pubkey(Q_candidate, (*this));
        cout << hex << "Q_candidate adresse = 0x" << key.getAddress() << endl;
        if( from_address.bitsize() == 160 && key.getAddress() != from_address )
        {
            ret = false;
            if( recover(Q_candidate, h, _r, _s, _parity, true) )
            {
                key = Pubkey(Q_candidate, (*this));
                ret = (key.getAddress() == from_address);
            }
        }
    }
    return ret;
}

Privkey::Privkey(const Integer& k, const EllipticCurve& curve)
    : _pubkey(curve.p_scalar(curve.getGenerator(), k), curve)
    , _secret(k, curve.getCurveOrder().size_in_base(2))
{
    assert(k>0 && k<curve.getCurveOrder());
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
        Integer n = curve.getCurveOrder();
        Integer s = a2Integer(&digest[0], 256); // first 256bits/512 = secret
        s += parent_privkey.getSecret();
        s %= n;
        const_cast<Bitstream&>(_secret).set(s, n.size_in_base(2));

        Bitstream cc(&digest[32], 256);
        _pubkey = Pubkey(curve.p_scalar(curve.getGenerator(), _secret), cc, curve);

        cout << "BIP32 " << index << (hardened ? "'" : "") << " chain code (hex): " << hex << _pubkey.getChainCode() << dec << endl;
        cout << "BIP32 " << index << (hardened ? "'" : "") << " secret (hex): " << hex << _secret << dec << endl;
        cout << "BIP32 " << index << (hardened ? "'" : "") << " public key (hex): " << hex << _pubkey.getKey(Pubkey::Format::PREFIXED_X) << dec << endl << endl;
    }
}

Privkey::Privkey(const Bitstream& seed, const EllipticCurve& curve)
{
    // Cf https://www.openssl.org/docs/manmaster/man3/HMAC.html
    // Cf https://www.openssl.org/docs/manmaster/man3/EVP_sha512.html

    Bitstream digest(Integer(0), 512);
    uint32_t dilen;

    unsigned char *res = HMAC( EVP_sha512(),
                               "Bitcoin seed", 12,
                               seed, (seed.bitsize()>>3),
                               digest, &dilen);
    if (res && dilen == 64)
    {
        cout << "BIP32 Root raw (hex): " << digest << dec << endl;

        Integer n = curve.getCurveOrder();
        Integer s = a2Integer(&digest[0], 256); // first 256bits/512 = secret
        s %= curve.getCurveOrder();
        const_cast<Bitstream&>(_secret).set(s, n.size_in_base(2));

        Bitstream cc(&digest[32], 256);
        _pubkey = Pubkey(curve.p_scalar(curve.getGenerator(), _secret), cc, curve);

        cout << "BIP32 " << "Root chain code (hex): " << hex << _pubkey.getChainCode() << dec << endl;
        cout << "BIP32 " << "Root secret (hex): " << hex << _secret << dec << endl;
        cout << "BIP32 " << "Root public key (hex): " << hex << _pubkey.getKey(Pubkey::Format::PREFIXED_X) << dec << endl << endl;
    }
}

//----------------------------------------------------------- BIP39 -----------------------------------------------------------------

Mnemonic::Mnemonic(const size_t entropy_bitsize, const vector<string> *dictionnary)
{
    div_t d;
    _dic = (dictionnary ? dictionnary : &BIP39::Dictionary::WordList_english);
    assert(_dic->size() > 1); // at least 2 elements
    // TOD: verify each element of the dictionnary is unique

    _went = log2(_dic->size());
    assert(_went <= 32); // max word entropy = 32 bits

    _ent = entropy_bitsize;
    assert(_ent >= 128); // for security
    d = div(_ent, 32);
    assert(!d.rem); // multiple of 32

    d = div(_ent, _went);
    _ms = d.quot + 1; // 1 extra word for checksum/alignment
    _cs = _went - d.rem;
}

bool Mnemonic::add_entropy(const string& entropy, const uint32_t bitsize, const uint8_t in_base)
{
    bool ret = false;
    if( _entropy.bitsize() + bitsize <= _ent)
    {
        _entropy.push_back(entropy, bitsize, in_base);
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
    dic_it = find(_dic->begin(), _dic->end(), data);
    if (dic_it != _dic->end() && _entropy.bitsize() < _ent)
    {
        bool is_last_word = (_entropy.bitsize() + _went > _ent);
        uint32_t controlled_went = _went;
        if (is_last_word)
            controlled_went -= _cs;
        uint32_t index = distance(_dic->begin(), dic_it);
        Bitstream e(_entropy);
        e.push_back(index >> (_went - controlled_went), controlled_went);
        if (!is_last_word || e.sha256().at(0,_cs).as_uint8() == (index & (0xFF >> (8 - _cs))))
        {
            _entropy = e;
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
    if (v.size() == _ms)
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
    return (_entropy.bitsize() == _ent);
}

void Mnemonic::clear()
{
    _entropy.clear();
}

const string Mnemonic::get_word_list() const
{
    string ret("");
    uint32_t nth_word;
    div_t d = div(_entropy.bitsize(), _went);
    for (int i = 0; i < d.quot; i++)
    {
        if(ret.size() > 0)
            ret += " ";
        ret += _dic->at(_entropy.at(i*_went,_went).as_uint16());
    }
    if (d.rem && is_valid())
        ret += " " + get_last_word();
    return ret;
}

bool Mnemonic::list_possible_last_word(vector<string> &list) const
{
    bool res = false;
    if (_entropy.bitsize() == _went * (_ms - 1))
    {
        list.clear();
        for (int i = 0; i < (1 << (_went - _cs)); i++)
        {
            Bitstream tmp(_entropy);
            tmp.push_back(i, _went - _cs);
            list.push_back(_dic->at((i << _cs) + tmp.sha256().at(0,_cs).as_uint8()));
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
        Integer index = (_entropy.at((_ms - 1)*_went, _went-_cs).as_uint8() << _cs) + _entropy.sha256().at(0,_cs).as_uint8();
        ret = _dic->at(index);
    }
    return ret;
}

void Mnemonic::print(bool as_index_list) const
{
    if (as_index_list)
        cout << _entropy << endl;
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
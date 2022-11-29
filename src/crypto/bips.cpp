#include <Common.h>

#include "EllipticCurve.h"
#include "bips.h"
#include "bip39_dictionnary.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <ethash/keccak.hpp>

using namespace BIP39;
using namespace BIP32;
using namespace ethash;

//----------------------------------------------------------- BIP32 -----------------------------------------------------------------
extpubkey::extpubkey(Secp256k1& curve, const bitstream& k, const bitstream& cc)   //from Curve + private key
    : key(curve.Gmul(k))
    , chaincode(cc)
{ }

const bitstream extpubkey::getKey(size_t size) const
{   
    Integer publicKey = key.getX();

    Integer prefix = 0;
    if( size == 33 )
        prefix = ((key.getY() % 2) ? 0x03 : 0x02);
    else if(size == 65)
        prefix = 0x04;

    publicKey += (prefix << 256);
    
    if( size == 64 | size == 65 )
    {
        publicKey <<= 256;
        publicKey += key.getY();
    }
    return bitstream(publicKey, (size<<3));
}

const bitstream extpubkey::getAddress() const
{
    hash256 h = keccak256(getKey(64), 64);
    return bitstream(&h.bytes[32 - 20], 160);
}

extprivkey::extprivkey(const extprivkey& parent, const int32_t index, const bool hardened)
    : secret()
    , pubkey(0)
{
    assert(index >= 0);

    bitstream parent_data;
    bitstream parent_cc(parent.getChainCode());
    uint32_t suffix = index;
    if(!hardened)
        parent_data.push_back(parent.getExtPubKey().getKey(33),8+256);
    else
    {
        parent_data.push_back(0x00,8);
        parent_data.push_back(parent.getSecret(),256);
        suffix += 0x80000000;
    }      
    parent_data.push_back(suffix, 32);
   
    bitstream digest(512);
    uint32_t dilen;
    unsigned char *res = ::HMAC(::EVP_sha512(),
                                parent_cc, 32,
                                parent_data, 33 + 4,
                                digest, &dilen);
    if (res && dilen == 64)
    {
        cout << "BIP32 " << dec << index << (hardened ? "'" : "") << " raw (hex): " << digest << dec << endl;
    
        Integer s = a2Integer(&digest[0], 256);
        s += parent.getSecret();
        s %= Secp256k1::GetInstance().getCurveOrder();
        secret.push_back(s, 256);

        bitstream cc(&digest[32], 256);
        pubkey = new extpubkey(Secp256k1::GetInstance(), secret, cc);

        cout << "BIP32 " << index << (hardened ? "'" : "") << " chain code (hex): " << hex <<  pubkey->getChainCode() << dec << endl;
        cout << "BIP32 " << index << (hardened ? "'" : "") << " secret (hex): " << hex << secret << dec << endl;
        cout << "BIP32 " << index << (hardened ? "'" : "") << " public key (hex): " << hex << pubkey->getKey(33) << dec << endl << endl;
    }
}

extprivkey::extprivkey(const bitstream& seed)
    : secret()
    , pubkey(0)
{
    // Cf https://www.openssl.org/docs/manmaster/man3/HMAC.html
    // Cf https://www.openssl.org/docs/manmaster/man3/EVP_sha512.html

    bitstream digest(512);
    uint32_t dilen;

    unsigned char *res = ::HMAC(::EVP_sha512(),
                                "Bitcoin seed", 12,
                                seed, (seed.bitsize()>>3),
                                digest, &dilen);
    if (res && dilen == 64)
    {
        cout << "BIP32 Root raw (hex): " << digest << dec << endl;

        bitstream s(&digest[0], 256);
        assert((Integer)s > 0 && (Integer)s < Secp256k1::GetInstance().getCurveOrder());
        secret = s;

        bitstream cc(&digest[32], 256);
        pubkey = new extpubkey(Secp256k1::GetInstance(), secret, cc);

        cout << "BIP32 " << "Root chain code (hex): " << hex <<  pubkey->getChainCode() << dec << endl;
        cout << "BIP32 " << "Root secret (hex): " << hex << secret << dec << endl;
        cout << "BIP32 " << "Root public key (hex): " << hex << pubkey->getKey(33) << dec << endl << endl;
    }
}

//----------------------------------------------------------- BIP39 -----------------------------------------------------------------

mnemonic::mnemonic(const size_t entropy_bitsize, const vector<string> *dictionnary)
    : entropy()
{
    div_t d;
    dic = (dictionnary ? dictionnary : &BIP39::Dictionary::WordList_english);
    assert(dic->size() > 1); // at least 2 elements
    // TOD: verify each element of the dictionnary is unique

    went = log2(dic->size());
    assert(went <= 32); // max word entropy = 32 bits

    ent = entropy_bitsize;
    assert(ent >= 128); // for security
    d = div(ent, 32);
    assert(!d.rem); // multiple of 32

    d = div(ent, (int)went);
    ms = d.quot + 1; // 1 extra word for checksum/alignment
    cs = went - d.rem;
}

bool mnemonic::add_word(const string &word)
{
    bool res = false;
    // TODO: remove case-sensitive
    vector<string>::const_iterator dic_it;
    dic_it = find(dic->begin(), dic->end(), word);
    if (dic_it != dic->end() && entropy.bitsize() < ent)
    {
        bool is_last_word = (entropy.bitsize() + went > ent);
        uint32_t controlled_went = went;
        if (is_last_word)
            controlled_went -= cs;
        uint32_t index = distance(dic->begin(), dic_it);
        bitstream e(entropy);
        e.push_back(index >> (went - controlled_went), controlled_went);
        if (!is_last_word || e.sha256().at(0,cs).as_uint8() == (index & (0xFF >> (8 - cs))))
        {
            entropy = e;
            res = true;
        }
    }
    if (!res)
        cout << "invalid word addition!" << endl;
    return res;
}

bool mnemonic::set_full_word_list(const string &list)
{
    bool res = false;
    vector<string> v = split(list, " ");
    if (v.size() == ms)
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

bool mnemonic::is_valid() const
{
    return (entropy.bitsize() == ent);
}

void mnemonic::clear()
{
    entropy.clear();
}

const string mnemonic::get_word_list() const
{
    string ret("");
    uint32_t nth_word;
    div_t d = div(entropy.bitsize(), went);
    for (int i = 0; i < d.quot; i++)
    {
        if(ret.size() > 0)
            ret += " ";
        ret += dic->at(entropy.at(i*went,went).as_uint16());
    }
    if (d.rem && is_valid())
        ret += " " + get_last_word();
    return ret;
}

bool mnemonic::list_possible_last_word(vector<string> &list) const
{
    bool res = false;
    if (entropy.bitsize() == went * (ms - 1))
    {
        list.clear();
        for (int i = 0; i < (1 << (went - cs)); i++)
        {
            bitstream tmp(entropy);
            tmp.push_back(i, went - cs);
            list.push_back(dic->at((i << cs) + tmp.sha256().at(0,cs).as_uint8()));
        }
        res = true;
    }
    return res;
}

const string mnemonic::get_last_word() const
{
    string ret("");
    if (is_valid())
    {
        Integer index = (entropy.at((ms - 1)*went, went-cs).as_uint8() << cs) + entropy.sha256().at(0,cs).as_uint8();
        ret = dic->at(index);
    }
    return ret;
}

void mnemonic::print(bool as_index_list) const
{
    if (as_index_list)
        cout << entropy << endl;
    else
        cout << get_word_list() << endl;
}

const bitstream mnemonic::get_seed(const string& pwd) const
{
    bitstream the_seed(512);
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
    }
    return the_seed;
}
#include "Common.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <ethash/keccak.hpp>

using namespace std;
using namespace Givaro;

Bitstream::Bitstream()
    : end_boffset(0)
{}

Bitstream::Bitstream(const Bitstream& b)
    : end_boffset(0)
{
    end_boffset = b.bitsize();
    vvalue = b.vvalue;   
}

Bitstream::Bitstream(const Integer& val, uint32_t bitsize)
    : end_boffset(0)
{
    set(val, bitsize);
}

Bitstream::Bitstream(const char* p, uint32_t bitsize)
    : end_boffset(0)
{
    set_from_ptr(reinterpret_cast<const u_int8_t*>(p), bitsize);
}

Bitstream::Bitstream(const uint8_t* p, uint32_t bitsize)
    : end_boffset(0)
{
    set_from_ptr(p, bitsize);
}

Bitstream::Bitstream(const string& str_value, const uint32_t bitsize, const uint8_t in_base)
    : end_boffset(0)
{
    push_back(str_value, bitsize, in_base);
}

void Bitstream::set(const Integer& val, uint32_t bitsize)
{
    if(end_boffset)
        clear();
    push_back(val, bitsize);
}

void Bitstream::set_from_ptr(const uint8_t* p, uint32_t bitsize)
{
    if(end_boffset)
        clear();
    div_t d = div(bitsize, 8);
    for(uint32_t i=0;i<d.quot;i++) vvalue.push_back(0);
    if(d.quot)
        memcpy(vvalue.data(), p, d.quot);
    if(d.rem)
        vvalue.push_back(p[d.quot] & ~(0xFF >> d.rem));
    end_boffset = bitsize;
}

struct cmp_str {
   bool operator()(char const *a, char const *b) const { return strcmp(a, b) < 0; }
};

void Bitstream::push_back(const string& str_value, const uint32_t bitsize, const uint8_t in_base)
{
    assert( in_base == 2 || in_base ==16 );

    const map<const char*, const uint8_t, cmp_str> m = { {"0", 0}, {"1", 1}, {"2", 2}, {"3", 3},
                                                         {"4", 4}, {"5", 5}, {"6", 6}, {"7", 7},
                                                         {"8", 8}, {"9", 9}, {"a", 10}, {"A", 10},
                                                         {"b", 11}, {"B", 11}, {"c", 12}, {"C", 12},
                                                         {"d", 13}, {"D", 13}, {"e", 14}, {"E", 14},
                                                         {"f", 15}, {"F", 15} };
    //Removes the 0x or 0b header
    string tmp = str_value;
    if( in_base == 2 && tmp.substr(0,1) == "0b" )
        tmp = tmp.substr(2, tmp.size() - 2);
    else if( in_base == 16 && tmp.substr(0,2) == "0x" )
        tmp = tmp.substr(2, tmp.size() - 2);
    
    //size specified must be greater or equal than the number intrinsic size
    assert(bitsize >= (tmp.size()<<(in_base == 2 ? 0 : 2)));

    Integer value(0);
    map<const char*, const uint8_t, cmp_str>::const_iterator it;
    while(tmp.size()>0)
    {
        it = m.find(tmp.substr(0, 1).c_str());
        assert( it != m.end() && ((*it).second == 0 || (*it).second == 1 || in_base == 16) );
        value <<= (in_base == 2 ? 1 : 4);
        value += (*it).second;
        tmp = tmp.substr(1, tmp.size() - 1);
    }
    push_back(value, bitsize);
}

void Bitstream::push_back(const Integer& bits_value, const uint32_t bitsize)
{
    Integer max_size_mask = Givaro::pow(2, bitsize) - 1;
    Integer bits_to_push(0);
    uint32_t nbitsleft = bitsize;
    while(nbitsleft)
    {   
        uint8_t nbits_to_push = min(8-(end_boffset%8), nbitsleft);
        bits_to_push = bits_value & (max_size_mask >> (bitsize - nbitsleft));
        bits_to_push >>= nbitsleft - nbits_to_push;
        if((end_boffset>>3) >= vvalue.size()) vvalue.push_back(0);  //overflow => resize
        vvalue[end_boffset>>3] += uint8_t(bits_to_push << (8-(end_boffset%8)-nbits_to_push));                
        end_boffset += nbits_to_push;
        nbitsleft -= nbits_to_push;
    }
}

const Bitstream Bitstream::at(uint32_t bitoffset, uint32_t bitsize) const       // not aligned
{
    assert(bitoffset+bitsize <= end_boffset);
    Integer mask = pow(2, bitsize) - 1;
    uint32_t rshift = end_boffset - bitoffset - bitsize;
    Integer v = mask & (Integer(*this)>>rshift);
    return Bitstream(v, bitsize);
}

void Bitstream::clear()
{
    end_boffset = 0;
    vvalue.clear();
}

const Bitstream Bitstream::sha256() const
{
    assert(!(end_boffset%8));
    Bitstream digest(Integer(0), 256);
    SHA256(*this, end_boffset>>3, digest);
    return digest;
}

const Bitstream Bitstream::keccak256() const
{
    assert(!(end_boffset%8));
    ethash::hash256 h = ethash::keccak256(*this, end_boffset>>3);
    Bitstream digest(h.bytes, 256);
    return digest;
}

const Bitstream Bitstream::address() const
{
    assert(!(end_boffset%8));
    ethash::hash256 h = ethash::keccak256(*this, end_boffset>>3);
    Bitstream digest(&h.bytes[32-20], 160);
    return digest;
}

ostream& operator<< (ostream& out, const Bitstream& v) {
    out << hex << Integer(v);
    return out;
}

Integer a2Integer(const uint8_t* input, const int32_t bitsize)
{
    Integer output = 0;
    if(bitsize>0)
    {
        div_t d = div(bitsize,8);
        for(int32_t index=0;index<d.quot;index++)
        {
            output += input[index];
            output <<= min(bitsize - ((index+1)<<3), 8);
        }
        if(d.rem)
            output += input[d.quot] >> (8 - d.rem);
    }
    return output;
}

// This function basically removes all separators and spreads the remaining words inside a vector
// The strict sequence (n x "1 word / 1 separator") is not verified (several consecutive separators
// are not interpreted as empty word(s); they are just removed)
vector<string> split(const string list, const string separator)
{
    vector<string> v;   
    int start = 0;
    int end = list.find(separator);
    while (end != -1) {
        if(end > start ) v.push_back(list.substr(start, end - start));
        start = end + separator.size();
        end = list.find(separator, start);
    }
    if(start != list.size()) v.push_back(list.substr(start, list.size() - start));
    return v;
}
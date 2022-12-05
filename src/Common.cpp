#include "Common.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <ethash/keccak.hpp>

using namespace std;
using namespace Givaro;

bitstream::bitstream()
    : end_boffset(0)
{}

/*bitstream::bitstream(const uint32_t reserve_bitsize)
    : end_boffset(reserve_bitsize)
{
    div_t d = div(reserve_bitsize, 8);
    uint32_t bytes = d.quot + (d.rem ? 1 : 0);
    for(uint32_t i=0;i<bytes;i++) vvalue.push_back(0);
}*/

bitstream::bitstream(const bitstream& b)
    : end_boffset(0)
{
    set(b);   
}

bitstream::bitstream(const Integer& val, uint32_t bitsize)
    : end_boffset(0)
{
    set_from_Integer(val, bitsize);
}

bitstream::bitstream(const char* p, uint32_t bitsize)
    : end_boffset(0)
{
    set_from_ptr(reinterpret_cast<const u_int8_t*>(p), bitsize);
}

bitstream::bitstream(const uint8_t* p, uint32_t bitsize)
    : end_boffset(0)
{
    set_from_ptr(p, bitsize);
}

void bitstream::set(const bitstream& b)
{
    end_boffset = b.bitsize();
    vvalue = b.vvalue;
}

void bitstream::set_from_Integer(const Integer& val, uint32_t bitsize)
{
    if(end_boffset)
        clear();
    push_back(val, bitsize);
}

void bitstream::set_from_ptr(const uint8_t* p, uint32_t bitsize)
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

void bitstream::push_back(const Integer& bits_value, const uint32_t bitsize)
{
    Integer max_size_mask = pow(Integer(2),bitsize) - 1;
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

const bitstream bitstream::at(uint32_t bitoffset, uint32_t bitsize) const       // not aligned
{
    assert(bitoffset+bitsize <= end_boffset);
    Integer mask = pow(Integer(2), bitsize) - 1;
    uint32_t rshift = end_boffset - bitoffset - bitsize;
    Integer v = mask & (Integer(*this)>>rshift);
    return bitstream(v, bitsize);
}

void bitstream::clear()
{
    end_boffset = 0;
    vvalue.clear();
}

const bitstream bitstream::sha256() const
{
    assert(!(end_boffset%8));
    bitstream digest(Integer(0), 256);
    SHA256(*this, end_boffset>>3, digest);
    return digest;
}

const bitstream bitstream::keccak256() const
{
    assert(!(end_boffset%8));
    ethash::hash256 h = ethash::keccak256(*this, end_boffset>>3);
    bitstream digest(h.bytes, 256);
    return digest;
}

const bitstream bitstream::address() const
{
    assert(!(end_boffset%8));
    ethash::hash256 h = ethash::keccak256(*this, end_boffset>>3);
    bitstream digest(&h.bytes[32-20], 160);
    return digest;
}

ostream& operator<< (ostream& out, const bitstream& v) {
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
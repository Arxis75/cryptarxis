#include "Common.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <ethash/keccak.hpp>

using namespace std;
using namespace Givaro;

bitstream::bitstream(const Integer& val, uint32_t bitsize)
    : end_boffset(0)
{
    if(bitsize)
        push_back(val, bitsize);
}

bitstream::bitstream(const uint8_t* p, uint32_t bitsize)
    : end_boffset(0)
{
    if(bitsize>0)
        push_back(getInteger(p, bitsize), bitsize);
}

bitstream::bitstream(const char* p, uint32_t size)
    : end_boffset(0)
{
    if(size>0)
    {
        Integer val(p[0]);
        for(uint32_t index=1;index<size;index++)
        {
            val <<= 8;
            val += p[index];
        }
        push_back(val, size<<3);
    }
}

void bitstream::push_back(const Integer& bits_value, const uint32_t bitsize)
{
    Integer max_size_mask = pow(Integer(2),bitsize) - 1;
    Integer bits_to_push(0u);
    uint32_t nbitsleft = bitsize;
    while(nbitsleft)
    {   
        uint8_t nbits_to_push = min(8-(end_boffset%8), nbitsleft);
        bits_to_push = bits_value & (max_size_mask >> (bitsize - nbitsleft));
        bits_to_push >>= nbitsleft - nbits_to_push;
        if((end_boffset>>3) >= vvalue.size()) vvalue.push_back(0u);  //overflow => resize
        vvalue[end_boffset>>3] += uint8_t(bits_to_push << (8-(end_boffset%8)-nbits_to_push));                
        end_boffset += nbits_to_push;
        nbitsleft -= nbits_to_push;
    }
}

bitstream::operator const Integer() const
{
    return getInteger(vvalue.data(), end_boffset);
}

const Integer bitstream::getInteger(const uint8_t* p, int32_t bitsize) const    // aligned
{
    Integer val(0u);
    if(bitsize>0)
    {
        div_t d = div(bitsize,8);
        for(uint32_t index=0;index<d.quot;index++)
        {
            val += p[index];
            val <<= min(bitsize - int32_t((index+1)<<3), 8);
        }
        if(d.rem)
            val += p[d.quot] >> (8 - d.rem);
    }
    return val;
}

const uint8_t* bitstream::ptr(uint32_t bytes_offset) const                      // aligned
{
    assert(((bytes_offset+1)<<3) <= end_boffset);
    return vvalue.data() + bytes_offset;
}

const bitstream bitstream::at(uint32_t bitoffset, uint32_t bitsize) const       // not aligned
{
    Integer v(0u);
    uint32_t at_end = bitoffset + bitsize;
    if( at_end <= end_boffset )
    {
        Integer mask = pow(Integer(2), bitsize) - 1;
        uint32_t rshift = end_boffset - at_end;
        v = mask & (getInteger(vvalue.data(),end_boffset)>>rshift);
    }
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
    bitstream digest(Integer(0),256);
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
    out << hex << v.getInteger(v.vvalue.data(), v.end_boffset);
    return out;
}

string b2a_hex(const uint8_t* p, const size_t n) {
    static const char hex[] = "0123456789abcdef";
    string res;
    res.reserve(n * 2);

    for (auto end = p + n; p != end; ++p) {
        const uint8_t v = (*p);
        res += hex[(v >> 4) & 0x0F];
        res += hex[v & 0x0F];
    }

    return res;
}

string b2a_bin(const uint8_t* p, const size_t n) {
    static const char bin[] = "01";
    string res;
    res.reserve(n * 2);

    for (auto end = p + n; p != end; ++p) {
        const uint8_t v = (*p);
        for(int i=7;i>=0;i--)
            res += bin[(v >> i) & 1];
    }

    return res;
}

template <typename T>
uint8_t* Vector_to_ByteArray(const vector<T>& v, uint8_t* a) {
    memset(a,0xFF,sizeof(T)*v.size());
    typename vector<T>::const_iterator iter;
    for(auto i=0;i<v.size();i++)
        for(auto j=0;j<sizeof(T);j++)
            *(a+i*sizeof(T)+j) = ((v[i]>>((sizeof(T)-j-1)<<3)) & 0xFF);
    return a;
}
template uint8_t* Vector_to_ByteArray<uint32_t>(const vector<uint32_t>& v, uint8_t* a); //for the linker

void ByteArray_to_GInteger(const uint8_t* input, Integer& output, const size_t input_size) {
    output = 0;
    if(input_size>0)
    {
        output = input[0];
        if(input_size>1)
        {
            int i;
            uint16_t shift = 8;
            for(i=1;i<input_size;i++)
            {
                output <<= shift;
                output += input[i];
            }
        }
    }
}

void GInteger_to_ByteArray(const Integer& input, uint8_t* output, const size_t output_size) {
    int i;
    Integer last_byte(0xFF);
    for(i=0;i<output_size;i++)
        output[i] = (input >> ((output_size-1-i) << 3)) & last_byte;
}

template <typename T> ostream& operator<< (ostream& out, const vector<T>& v) {
    for(auto i: v) out << i;
    return out;
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
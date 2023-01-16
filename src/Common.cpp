#include "Common.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <ethash/keccak.hpp>
#include <algorithm>

using namespace std;
using namespace Givaro;

struct cmp_str {
    bool operator()(char const *a, char const *b) const { return strcmp(a, b) < 0; }
};

static const map<const char*, const uint8_t, cmp_str> map_hexa_chars = { {"0", 0}, {"1", 1}, {"2", 2}, {"3", 3},
                                                            {"4", 4}, {"5", 5}, {"6", 6}, {"7", 7},
                                                            {"8", 8}, {"9", 9}, {"a", 10}, {"A", 10},
                                                            {"b", 11}, {"B", 11}, {"c", 12}, {"C", 12},
                                                            {"d", 13}, {"D", 13}, {"e", 14}, {"E", 14},
                                                            {"f", 15}, {"F", 15} };
BitStream::BitStream()
    : end_boffset(0)
{}

BitStream::BitStream(const BitStream& b)
    : end_boffset(0)
{
    end_boffset = b.bitsize();
    vvalue = b.vvalue;   
}

BitStream::BitStream(const Integer& val, uint32_t bitsize)
    : end_boffset(0)
{
    set(val, bitsize);
}

BitStream::BitStream(const char *p, uint32_t bitsize)
    : end_boffset(0)
{
    set_from_ptr(reinterpret_cast<const u_int8_t*>(p), bitsize);
}

BitStream::BitStream(const uint8_t *p, uint32_t bitsize)
    : end_boffset(0)
{
    set_from_ptr(p, bitsize);
}

BitStream::BitStream(const string& str_value, const uint32_t bitsize, const uint8_t in_base)
    : end_boffset(0)
{
    push_back(str_value, bitsize, in_base);
}

void BitStream::set(const Integer& val, uint32_t bitsize)
{
    if(end_boffset)
        clear();
    push_back(val, bitsize);
}

void BitStream::set_from_ptr(const uint8_t *p, uint32_t bitsize)
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

void BitStream::push_back(const string& str_value, const uint32_t bitsize, const uint8_t in_base)
{
    assert( in_base == 2 || in_base ==16 );

    //Removes the 0x or 0b header if necessary
    string tmp = str_value;
    if( in_base == 16 && tmp.substr(0, 2) == "0x" )
        tmp = tmp.substr(2, tmp.size() - 2);
    else if( in_base == 2 && tmp.substr(0, 2) == "0b" )
        tmp = tmp.substr(2, tmp.size() - 2);

    Integer value(0);
    while(tmp.size()>0)
    {
        auto it = map_hexa_chars.find(tmp.substr(0, 1).c_str());
        assert( it != map_hexa_chars.end() && (in_base == 16 || (*it).second == 0 || (*it).second == 1) );
        value <<= (in_base == 16 ? 4 : 1);
        value += (*it).second;
        tmp = tmp.substr(1, tmp.size() - 1);
    }
    push_back(value, bitsize);
}

void BitStream::push_back(const Integer& bits_value, const uint32_t bitsize)
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

const BitStream BitStream::at(uint32_t bitoffset, uint32_t bitsize) const       // not aligned
{
    assert(bitoffset+bitsize <= end_boffset);
    Integer mask = pow(2, bitsize) - 1;
    uint32_t rshift = end_boffset - bitoffset - bitsize;
    Integer v = mask & (Integer(*this)>>rshift);
    return BitStream(v, bitsize);
}

void BitStream::clear()
{
    end_boffset = 0;
    vvalue.clear();
}

const BitStream BitStream::sha256() const
{
    assert(!(end_boffset%8));
    BitStream digest(Integer::zero, 256);
    SHA256(*this, end_boffset>>3, digest);
    return digest;
}

const BitStream BitStream::keccak256() const
{
    assert(!(end_boffset%8));
    ethash::hash256 h = ethash::keccak256(*this, end_boffset>>3);
    BitStream digest(h.bytes, 256);
    return digest;
}

const BitStream BitStream::address() const
{
    assert(!(end_boffset%8));
    ethash::hash256 h = ethash::keccak256(*this, end_boffset>>3);
    BitStream digest(&h.bytes[32-20], 160);
    return digest;
}

const Integer BitStream::a2Integer(const uint8_t *input, const int32_t bitsize) const
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

ostream& operator<< (ostream& out, const BitStream& v) {
    out << hex << Integer(v);
    return out;
}

//---------------------------------------------------------------------------------------------------------------------------------
ByteStream::ByteStream()
{
    //default size for processing time optimization (memory consumming though)
    vvalue.reserve(32);
}

ByteStream::ByteStream(const Integer& value, uint32_t size)
{
    vvalue.reserve(size);
    uint32_t value_size = (size > sizeInBytes(value) ? sizeInBytes(value) : size);
    uint32_t extra_size = size - value_size;
    for(int i=0;i<extra_size;i++)
        vvalue.push_back(0x00);
    for(int i=1;i<=value_size;i++)
        vvalue.push_back(0xFF & uint8_t(value>>((value_size-i)<<3)));
}

void ByteStream::set_from_ptr(const uint8_t *p, uint32_t size)
{
    clear();
    vvalue.reserve(size);
    for(uint32_t i=0;i<size;i++)
        vvalue.push_back(p[i]);
}

void ByteStream::push_back(const string& str_value, const uint32_t size, const uint8_t in_base)
{
    assert( in_base == 2 || in_base ==16 );
    
    //Removes the 0x or 0b header if necessary
    string tmp = str_value;
    if( in_base == 16 && tmp.substr(0,2) == "0x" )
        tmp = tmp.substr(2, tmp.size() - 2);
    else if( in_base == 2 && tmp.substr(0,2) == "0b" )
        tmp = tmp.substr(2, tmp.size() - 2);

    //Forces byte-alignment
    int32_t front_zero_padding_size = (in_base == 16 ? tmp.size()%2 : tmp.size()%8);
    while( front_zero_padding_size )
    {
        tmp = string("0") + tmp;
        front_zero_padding_size = (in_base == 16 ? tmp.size()%2 : tmp.size()%8);
    }

    //Stores front 00-padding according to "size"
    front_zero_padding_size = size - (in_base == 16 ? tmp.size()>>1 : tmp.size()>>3);
    for(int i=0;i<front_zero_padding_size;i++)
        vvalue.push_back(0x00);

    //If empty ByteStream, optimizes the memory allocation
    if( !byteSize() )
        vvalue.reserve(in_base == 16 ? tmp.size()>>1 : tmp.size()>>3);

    while(tmp.size()>0)
    {
        uint8_t value = 0;
        uint8_t nb_chars_in_one_byte = (in_base == 16 ? 2 : 8);
        for(int i=0;i<nb_chars_in_one_byte;i++)
        {
            auto it = map_hexa_chars.find(tmp.substr(0, 1).c_str());
            assert( it != map_hexa_chars.end() && (in_base == 16 || (*it).second == 0 || (*it).second == 1) );
            value <<= (in_base == 16 ? 4 : 1);
            value += (*it).second;
            tmp = tmp.substr(1, tmp.size() - 1);
        }
        vvalue.push_back(value);
    }
}

void ByteStream::push_back(const uint64_t value, uint32_t size)
{
    uint32_t value_size = (size > 8 ? 8 : size);
    uint32_t extra_size = size - value_size;
    for(int i=0;i<extra_size;i++)
        vvalue.push_back(0x00);
    for(int i=1;i<=value_size;i++)
        vvalue.push_back(0xFF & uint8_t(value>>((value_size-i)<<3)));
 };


const ByteStream ByteStream::sha256() const
{
    char zero[32];
    memset(&zero,0,sizeof(zero));
    ByteStream digest(zero, sizeof(zero));
    SHA256(*this, byteSize(), digest);
    return digest;
}

const ByteStream ByteStream::keccak256() const
{
    ethash::hash256 h = ethash::keccak256(*this, byteSize());
    ByteStream digest(h.bytes, 32);
    return digest;
}

const ByteStream ByteStream::address() const
{
    ethash::hash256 h = ethash::keccak256(*this, byteSize());
    ByteStream digest(&h.bytes[32-20], 20);
    return digest;
}

const Integer ByteStream::a2Integer(const uint8_t *input, const int32_t size) const
{
    Integer output = 0;
    if(size>0)
    {
        for(int32_t index=0;index<size;index++)
        {
            output <<= 8;
            output += input[index];
        }
    }
    return output;
}

ostream& operator<< (ostream& out, const ByteStream& v) {
    out << hex << Integer(v);
    return out;
}

//-------------------------------------------------------------------------------------------------------------------------------------

RLPByteStream::RLPByteStream(const uint64_t val, uint32_t size)
    : ByteStream()
{
    //Avoids call to the ByteStream(const Integer& value, uint32_t size) constructor
    ByteStream b;
    b.push_back(val, size);
    fromByteStream(b);
}

RLPByteStream::RLPByteStream(const vector<RLPByteStream> rlp_list)
    : ByteStream()
{
    if(rlp_list.size() > 0)
    {
        ByteStream rlp_payload;
        for(int i=0;i<rlp_list.size();i++)
            rlp_payload.push_back(rlp_list[i]);   
        
        uint64_t rlp_payload_size = rlp_payload.byteSize();
        if( rlp_payload_size <= 55 )
        {
            push_back(0xC0 + rlp_payload_size, 1);
            push_back(rlp_payload);
        }
        else
        {
            uint8_t list_size_size_nbits = log2(rlp_payload_size);  //Ca marche pas
            uint8_t list_size_size = (list_size_size_nbits>>3) + ((list_size_size_nbits%8) ? 1 : 0);
            push_back(0xF7 + list_size_size, 1);
            push_back(rlp_payload_size, list_size_size);
            push_back(rlp_payload);
        }
    }
    else
        push_back(0xC0, 1);
}

void RLPByteStream::fromByteStream(const ByteStream& field)
{   
    uint64_t field_size = field.byteSize();
    if( field_size )
    {
        if( field_size == 1 && field.as_uint8() <= 0x7F )
            push_back(field);
        else
        {
            if( field_size <= 55 )
            {   
                push_back(0x80 + field_size, 1);
                push_back(field);
            }
            else
            {
                uint8_t field_size_size_nbits = log2(field_size);  //Ca marche pas
                uint8_t field_size_size = (field_size_size_nbits>>3) + ((field_size_size_nbits%8) ? 1 : 0);
                push_back(0xB7 + field_size_size, 1);
                push_back(field_size, field_size_size);
                push_back(field);
            }
        }
    }
    else
        push_back(0x80, 1);       
}

//-------------------------------------------------------------------------------------------------------------------------

// This function basically removes all separators and spreads the remaining words inside a vector
// The strict sequence (n x "1 word / 1 separator") is not verified (several consecutive separators
// are not interpreted as empty word(s); they are just removed)
vector<string> split(const string& list, const string& separator)
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

static inline uint32_t log2(const uint32_t x) {
  uint32_t y;
  asm ( "\tbsr %1, %0\n"
      : "=r"(y)
      : "r" (x)
  );
  return y;
}
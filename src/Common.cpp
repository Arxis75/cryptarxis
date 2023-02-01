#include "Common.h"
#include <tools/tools.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <ethash/keccak.hpp>

#include <map>
#include <algorithm>

using Givaro::Integer;
using std::map;
using std::cout;
using std::cerr;
using std::hex;
using std::dec;
using std::endl;

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

BitStream::BitStream(const Integer& val, uint64_t bitsize)
    : end_boffset(0)
{
    set(val, bitsize);
}

BitStream::BitStream(const char *p)
    : end_boffset(0)
{
    push_back_ptr(reinterpret_cast<const u_int8_t*>(p), strlen(p)<<3);
}

BitStream::BitStream(const uint8_t *p, uint64_t bitsize)
    : end_boffset(0)
{
    push_back_ptr(p, bitsize);
}

BitStream::BitStream(const string& str_value, const uint64_t bitsize, const uint8_t in_base)
    : end_boffset(0)
{
    push_back(str_value, bitsize, in_base);
}

void BitStream::set(const Integer& val, uint64_t bitsize)
{
    if(end_boffset)
        clear();
    push_back(val, bitsize);
}

void BitStream::push_back_ptr(const uint8_t *p, uint64_t bitsize)
{
    div_t d = div(bitsize, 8);
    for(uint64_t i=0;i<d.quot;i++) vvalue.push_back(0);
    if(d.quot)
        memcpy(vvalue.data(), p, d.quot);
    if(d.rem)
        vvalue.push_back(p[d.quot] & ~(0xFF >> d.rem));
    end_boffset = bitsize;
}

void BitStream::push_back(const string& str_value, const uint64_t bitsize, const uint8_t in_base)
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

void BitStream::push_back(const Integer& bits_value, const uint64_t bitsize)
{
    Integer max_size_mask = Givaro::pow(2, bitsize) - 1;
    Integer bits_to_push(0);
    uint64_t nbitsleft = bitsize;
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

const BitStream BitStream::at(uint64_t bitoffset, uint64_t bitsize) const       // not aligned
{
    assert(bitoffset+bitsize <= end_boffset);
    Integer mask = pow(2, bitsize) - 1;
    uint64_t rshift = end_boffset - bitoffset - bitsize;
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
ByteStream::ByteStream(const Integer& value, uint64_t size)
{
    vvalue.reserve(size);
    uint64_t value_size = (size > sizeInBytes(value) ? sizeInBytes(value) : size);
    uint64_t extra_size = size - value_size;
    for(int i=0;i<extra_size;i++)
        vvalue.push_back(0x00);
    for(int i=1;i<=value_size;i++)
        vvalue.push_back(0xFF & uint8_t(value>>((value_size-i)<<3)));
}

void ByteStream::push_back_ptr(const uint8_t *p, uint64_t size)
{
    for(uint64_t i=0;i<size;i++)
        vvalue.push_back(p[i]);
}

void ByteStream::push_back(const string& str_value, const uint64_t size, const uint8_t in_base)
{
    assert( in_base == 2 || in_base ==16 );
    
    //Removes the 0x or 0b header if necessary
    string tmp = str_value;
    if( in_base == 16 && tmp.substr(0,2) == "0x" )
        tmp = tmp.substr(2, tmp.size() - 2);
    else if( in_base == 2 && tmp.substr(0,2) == "0b" )
        tmp = tmp.substr(2, tmp.size() - 2);

    //Forces byte-alignment if ncesessary
    int32_t front_zero_padding_size = (in_base == 16 ? tmp.size()%2 : tmp.size()%8);
    while( front_zero_padding_size )
    {
        tmp = string("0") + tmp;
        front_zero_padding_size = (in_base == 16 ? tmp.size()%2 : tmp.size()%8);
    }

    //Stores front 00-padding according to "size" if ncesessary
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

void ByteStream::push_back(const uint64_t value, const uint64_t size)
{
    //Factorize code with push_front(const uint64_t value, const uint64_t size)
    ByteStream b;
    uint64_t value_size = (size > 8 ? 8 : size);
    uint64_t extra_size = size - value_size;
    for(int i=0;i<extra_size;i++)
        b.vvalue.push_back(0x00);
    for(int i=1;i<=value_size;i++)
        b.vvalue.push_back(0xFF & uint8_t(value>>((value_size-i)<<3)));
    push_back(b);
 };

const void ByteStream::push_front(const uint64_t value, const uint64_t size)
{
    //Factorize code with push_back(const uint64_t value, const uint64_t size)
    ByteStream b;
    uint64_t value_size = (size > 8 ? 8 : size);
    uint64_t extra_size = size - value_size;
    for(int i=0;i<extra_size;i++)
        b.vvalue.push_back(0x00);
    for(int i=1;i<=value_size;i++)
        b.vvalue.push_back(0xFF & uint8_t(value>>((value_size-i)<<3)));
    push_front(b);
}

const ByteStream ByteStream::pop_front(const uint64_t size)
{
    if( size )
    {
        if( size < byteSize() )
        {
            ByteStream retval(&(*this)[0], size);
            memmove(&(*this)[0], &(*this)[size], byteSize() - size);    //overlapping memcpy
            for(int i=0;i<size;i++)
                vvalue.pop_back();
            return retval;
        }
        else
        {
            if( size > byteSize() )
                cerr << "Warning! ByteStream::pop_front() asked to pop data larger than the ByteStream size! The whole buffer was poped but not more..." << endl;
            ByteStream retval(*this);
            clear();
            return retval;
        }
    }
    else
        return ByteStream();
}

const ByteStream ByteStream::sha256() const
{
    uint8_t zero[32];
    memset(&zero,0,sizeof(zero));
    ByteStream digest(&zero[0], sizeof(zero));
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

ByteStream::operator const string() const
{
    uint64_t size = byteSize();
    string s("");
    for (uint64_t i = 0; i < size; i++)
        s += vvalue[i];
    return s;
}

const uint64_t ByteStream::as_uint64() const
{
    uint64_t retval = 0;
    if( vvalue.size() )
    {
        uint8_t s_1 = vvalue.size() - 1;
        if(s_1 > 7)     
            s_1 = 7;    // 7 = 8 bytes (uint64_t) - 1
        for(int i=0;i<=s_1;i++)
            retval += uint64_t(vvalue[i]) << ((s_1 - i) << 3 );
    }
    return retval;
}

ostream& operator<< (ostream& out, const ByteStream &v) {
    out << hex << Integer(v);
    return out;
}

//-------------------------------------------------------------------------------------------------------------------------------------

RLPByteStream::RLPByteStream(const ByteStream &to_rlp_encode, const bool as_list)
{
    //MAIN RLP ENCODING METHOD
    if( to_rlp_encode.byteSize() )
    {
        // The only use-case of as_list = true here is to rebuild the list header
        // from a truncated RLP list.The truncated RLPByteStream is passed
        // as a simple ByteStream
        uint8_t extra_prefix = (as_list ? 0x40 : 0);
        if(to_rlp_encode.byteSize() == 1 && to_rlp_encode[0] < 0x80)
        {
            if( as_list)
                ByteStream::push_back(0xC1, 1);
        }
        else if( to_rlp_encode.byteSize() <= 55 )
            ByteStream::push_back(0x80 + extra_prefix + to_rlp_encode.byteSize(), 1);
        else
        {
            uint64_t size_size = sizeInBytes64(to_rlp_encode.byteSize());
            ByteStream::push_back(0xB7 + extra_prefix + size_size, 1);
            ByteStream::push_back(to_rlp_encode.byteSize() , size_size);
        }
        ByteStream::push_back(to_rlp_encode);
    }
    else
        ByteStream::push_back((as_list ? 0xC0 : 0x80), 1);
}

void RLPByteStream::push_back(const RLPByteStream &rlp, const bool at_top_level)
{
    //MAIN RLP LIST ENCODING METHOD
    if( byteSize() )    
    {
        //There is already some RLP data
        uint64_t list_size = byteSize();
        uint8_t list_size_size = 0;
        
        uint8_t front_header = vvalue[0];

        if( !at_top_level && front_header >= 0xC0 )
        {
            //Drops the previous list header
            ByteStream::pop_front(1);
            if( front_header > 0xF7 )
            {
                list_size_size = front_header - 0xF7;
                ByteStream::pop_front(list_size_size);
            }
        }
        // Creates a new list header
        list_size = byteSize() + rlp.byteSize();
        if(list_size > 55)
        {
            list_size_size = sizeInBytes64(list_size);
            ByteStream::push_front(list_size, list_size_size);
        }
        ByteStream::push_front((list_size <= 55 ? 0xC0 + list_size : 0xF7 + list_size_size), 1);
    }
    ByteStream::push_back(rlp);
}

void RLPByteStream::push_front(const RLPByteStream &rlp, const bool at_top_level)
{
    //MAIN RLP LIST ENCODING METHOD
    if( byteSize() )    
    {
        //There is already some RLP data
        uint64_t list_size = byteSize();
        uint8_t list_size_size = 0;
        
        uint8_t front_header = vvalue[0];

        if( !at_top_level && front_header >= 0xC0 )
        {
            //Drops the previous list header
            ByteStream::pop_front(1);
            if( front_header > 0xF7 )
            {
                list_size_size = front_header - 0xF7;
                ByteStream::pop_front(list_size_size);
            }
        }

        ByteStream::push_front(rlp);

        // Creates a new list header
        list_size = byteSize();
        if(list_size > 55)
        {
            list_size_size = sizeInBytes64(list_size);
            ByteStream::push_front(list_size, list_size_size);
        }
        ByteStream::push_front((list_size <= 55 ? 0xC0 + list_size : 0xF7 + list_size_size), 1);
    }
    else
        ByteStream::push_front(rlp);
}

RLPByteStream RLPByteStream::pop_front(bool &is_list)
{
    is_list = false;
    RLPByteStream retval;
    if( byteSize() )
    {   
        uint8_t front_header = vvalue[0], front_elem_size_size = 0;
        uint64_t front_header_size = 0, front_elem_size = 0;
        bool rebuild_header = false;
        
        if( front_header >= 0xC0 )
        {
            //Drops the previous list header
            ByteStream::pop_front(1);
            if( front_header >= 0xF7 )
            {
                uint8_t list_size_size = front_header - 0xF7;
                ByteStream::pop_front(list_size_size);
            }
            rebuild_header = true;
        }
        if( byteSize() )
        {
            front_header = vvalue[0];

            if( front_header < 0x80 )       //[0x00, 0x7f] 
            {
                front_elem_size = 1;
                front_header_size = 0;
                is_list = false;
            }
            else if( front_header < 0xB8 )  //[0x80, 0xb7]
            {
                front_elem_size = front_header - 0x80;
                front_header_size = 1;
                is_list = false;
            }
            else if( front_header < 0xC0 )   //[0xb8, 0xbf]
            {
                front_elem_size_size = front_header - 0xB7;
                if( front_elem_size_size < byteSize() )
                    front_elem_size = ByteStream(&vvalue[1], front_elem_size_size).as_uint64();
                else
                {
                    cerr << "Warning! ByteStream::pop_front() found a wrong RLP encoding! Doing our best..." << endl;
                    front_elem_size = 0;
                }
                front_header_size = 1 + front_elem_size_size;
                is_list = false;
            }
            else if( front_header < 0xF8 )  //[0xc0, 0xf7]
            {
                //Do not remove the header of the sub-list when poping it:
                front_elem_size = 1 + front_header - 0xC0;
                front_header_size = 0;
                is_list = true;
            }
            else //[0xf8, 0xff] 
            {
                front_elem_size_size = front_header - 0xF7;//Do not remove the header of the sub-list when poping it
                if( front_elem_size_size < byteSize() )
                    //Do not remove the header of the sub-list when poping it:
                    front_elem_size = 1 + front_elem_size_size + ByteStream(&vvalue[1], front_elem_size_size).as_uint64();
                else
                {
                    cerr << "Warning! ByteStream::pop_front() found a wrong RLP encoding! Doing our best..." << endl;
                    front_elem_size = 1;
                }
                front_header_size = 0;
                is_list = true;
            }

            //Drops the first RLP element header (only if not list)
            ByteStream::pop_front(front_header_size);
            // Pops the first element (with header if list): the low-level vector copy
            // prevents the ByteStream to get re-RLP-encoded
            *static_cast<ByteStream*>(&retval) = ByteStream::pop_front(front_elem_size);

            if( byteSize() && rebuild_header )
            {
                //Rebuilds the list header if necessary
                RLPByteStream b((*this), true);
                vvalue = b.vvalue;
            }
        }
    }
    return retval;
}
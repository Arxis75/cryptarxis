#pragma once

#include <givaro/modular-integer.h>

#include <map>

using namespace std;
using namespace Givaro;

static const int log2_tab64[64] = {
    63,  0, 58,  1, 59, 47, 53,  2,
    60, 39, 48, 27, 54, 33, 42,  3,
    61, 51, 37, 40, 49, 18, 28, 20,
    55, 30, 34, 11, 43, 14, 22,  4,
    62, 57, 46, 52, 38, 26, 32, 41,
    50, 36, 17, 19, 29, 10, 13, 21,
    56, 45, 25, 31, 35, 16,  9, 12,
    44, 24, 15,  8, 23,  7,  6,  5};

static inline int log2_64 (uint64_t value)
{
    value |= value >> 1;
    value |= value >> 2;
    value |= value >> 4;
    value |= value >> 8;
    value |= value >> 16;
    value |= value >> 32;
    return log2_tab64[((uint64_t)((value - (value >> 1))*0x07EDD5E59A4E28C2)) >> 58];
}

static inline uint64_t sizeInBytes64(const uint64_t& value)
{
    return 1 + (log2_64(value)>>3);
}

class BitStream
{
    public:
        BitStream();
        BitStream(const BitStream&);
        BitStream(const char *p);
        BitStream(const uint8_t *p, uint64_t bitsize);
        // For BigInt: BEWARE possible implicit conversion from const char* to Integer when calling the constructor
        // For construction from an array of chars, the caller must use ByteStream(const char* str) signature.
        // For construction from value=0, the caller must explicitely use Integer::zero or Integer(0), else, it could
        // lead to ByteStream(const uint8_t *p, uint64_t size) being called.
        BitStream(const Integer& val, uint64_t bitsize);
        BitStream(const string& str_value, const uint64_t bitsize, const uint8_t in_base);
        
        void set(const Integer& val, const uint64_t bitsize);
        void push_back(const Integer& bits_value, const uint64_t bitsize);
        void push_back_ptr(const uint8_t *p, const uint64_t bitsize);
        void push_back(const string& str_value, const uint64_t bitsize, const uint8_t in_base);
        void clear();
        
        const uint64_t bitsize() const { return end_boffset; }

        const BitStream sha256() const;
        const BitStream keccak256() const;
        const BitStream address() const;

        friend ostream& operator<<(ostream& out, const BitStream& v);
        
        operator uint8_t*() { return reinterpret_cast<uint8_t*>(vvalue.data()); }
        operator const unsigned char*() const { return reinterpret_cast<const unsigned char*>(vvalue.data()); }     
        operator const Integer() const { return a2Integer(vvalue.data(), end_boffset); }

        inline bool operator==(const BitStream& b) const { return Integer(*this) == Integer(b); }
        inline bool operator!=(const BitStream& b) const { return Integer(*this) != Integer(b); }
        inline bool operator< (const BitStream& b) const { return Integer(*this) <  Integer(b); }
        inline bool operator> (const BitStream& b) const { return Integer(*this) >  Integer(b); }
        inline bool operator<=(const BitStream& b) const { return Integer(*this) <= Integer(b); }
        inline bool operator>=(const BitStream& b) const { return Integer(*this) >= Integer(b); }

        //Unaligned operators
        const BitStream at(const uint64_t bitoffset, const uint64_t bitsize) const;
        uint8_t as_uint8(uint64_t bofs = 0) const { return Integer(at(bofs, min(bofs+8, end_boffset) - bofs)); }
        uint16_t as_uint16(uint64_t bofs = 0) const { return Integer(at(bofs, min(bofs+16, end_boffset) - bofs)); }
        uint32_t as_uint32(uint64_t bofs = 0) const { return Integer(at(bofs, min(bofs+32,end_boffset) - bofs)); }
        uint64_t as_uint64(uint64_t bofs = 0) const { return Integer(at(bofs, min(bofs+64,end_boffset) - bofs)); }
        Integer as_Integer(uint64_t bofs = 0) const { return Integer(at(bofs, end_boffset - bofs)); }

    protected:
        const Integer a2Integer(const uint8_t *input, const int32_t bitsize) const;

    private:
        uint64_t end_boffset;
        vector<uint8_t> vvalue;
};

class ByteStream
{
    public:       
        ByteStream() { vvalue.reserve(32); };
        ByteStream(const uint64_t value) { vvalue.reserve(8); push_back(value, sizeInBytes64(value)); }
        ByteStream(const ByteStream &b) { vvalue = b.vvalue; }
        ByteStream(const char* str) { vvalue.reserve(strlen(str)); push_back_ptr(reinterpret_cast<const uint8_t*>(str), strlen(str)); }
        ByteStream(const uint8_t *p, uint64_t size) { vvalue.reserve(size); push_back_ptr(p, size); }
        // For BigInt: BEWARE possible implicit conversion from const char* to Integer when calling the constructor
        // For construction from an array of chars, the caller must use ByteStream(const char* str) signature.
        // For construction from value=0, the caller must explicitely use Integer::zero or Integer(0), else, it could
        // lead to ByteStream(const uint8_t *p, uint64_t size) being called.
        ByteStream(const Integer& value, uint64_t size);
        // For string representing a number in base 2 or 16
        ByteStream(const string& str_value, const uint64_t size, const uint8_t in_base) { vvalue.reserve(size); push_back(str_value, size, in_base); };

        void push_back(const ByteStream &b) { vvalue.insert(vvalue.end(), b.vvalue.begin(), b.vvalue.end()); }
        void push_back(const uint64_t value, const uint64_t size);
        void push_back_ptr(const uint8_t *p, const uint64_t size);
        void push_back(const string& str_value, const uint64_t size, const uint8_t in_base);

        const void push_front(ByteStream b) { b.push_back(*this); vvalue = b.vvalue; };
        const void push_front(const uint64_t value, const uint64_t size);
        const ByteStream pop_front(const uint64_t size);

        const ByteStream sha256() const;
        const ByteStream keccak256() const;
        const ByteStream address() const;

        friend ostream& operator<<(ostream& out, const ByteStream &v);

        inline void clear() { vvalue.clear(); }
        inline const uint64_t byteSize() const { return vvalue.size(); }

        inline operator uint8_t*() { return reinterpret_cast<uint8_t*>(vvalue.data()); }
        inline operator const unsigned char*() const { return reinterpret_cast<const unsigned char*>(vvalue.data()); }     
        inline operator const Integer() const { return as_Integer(); }
        operator const string() const;  // inline in the .cpp does not compile!?!

        inline bool operator==(const ByteStream &b) const { return vvalue == b.vvalue; }
        inline bool operator!=(const ByteStream &b) const { return vvalue != b.vvalue; }
        //inline bool operator< (const ByteStream &b) const { return Integer(*this) <  Integer(b); }
        //inline bool operator> (const ByteStream &b) const { return Integer(*this) >  Integer(b); }
        //inline bool operator<=(const ByteStream &b) const { return Integer(*this) <= Integer(b); }
        //inline bool operator>=(const ByteStream &b) const { return Integer(*this) >= Integer(b); }

        //Unaligned operators
        //inline const ByteStream at(const uint64_t offset, const uint64_t size) const { return ByteStream(&vvalue.data()[offset], size); };
        inline const uint8_t as_uint8() const { return (byteSize()>0 ? vvalue[0] : 0); }
        inline const uint64_t as_uint64() const;
        const Integer as_Integer() const { return a2Integer(vvalue.data(), vvalue.size()); }

    protected:
        const Integer a2Integer(const uint8_t *input, const int32_t size) const;

    protected:
        vector<uint8_t> vvalue;
};

class RLPByteStream: public ByteStream
{
    public:
        // Non-encoding constructors:
        RLPByteStream() { vvalue.reserve(1+32); }
        RLPByteStream(const RLPByteStream &b) : ByteStream(b) {}
        RLPByteStream(const uint8_t *p, uint64_t size) : ByteStream(p, size) { }
        RLPByteStream(const char* str) : ByteStream(str, strlen(str)>1, 16) { }
        
        // Encoding constructor:
        // "as_list" is used to:
        //      - rebuild an erased list header,
        //      - discriminates for an empty input between 0x80 and 0xC0
        RLPByteStream(const ByteStream &to_rlp_encode, const bool as_list = false);

        // Push/Pop Elements to/from a serialized RLP
        // "at_top_level" used to choose between putting under existing list (false) or
        // putting at the same level as an existing list (true), thus creating a new top-list
        void push_back(const RLPByteStream& rlp, const bool at_top_level = false);
        void push_front(const RLPByteStream& rlp, const bool at_top_level = false);
        ByteStream pop_front();
};

// This function basically removes all separators and spreads the remaining words inside a vector
// The strict sequence (n x "1 word / 1 separator") is not verified (several consecutive separators
// are not interpreted as empty word(s); they are just removed)
vector<string> split(const string& list, const string& separator);

static inline uint64_t sizeInBytes(const Integer& value)
{
    uint64_t tmp = value.size_in_base(2);
    return (tmp>>3) + (tmp%8);
}
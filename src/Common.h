#pragma once

#include <givaro/modular-integer.h>

#include <map>
using namespace std;
using namespace Givaro;

class BitStream
{
    public:
        BitStream();
        BitStream(const BitStream&);
        BitStream(const Integer& val, uint32_t bitsize);
        BitStream(const char *p, uint32_t bitsize);
        BitStream(const uint8_t *p, uint32_t bitsize);
        BitStream(const string& str_value, const uint32_t bitsize, const uint8_t in_base);
        
        void set(const Integer& val, const uint32_t bitsize);
        void push_back(const Integer& bits_value, const uint32_t bitsize);
        void push_back_ptr(const uint8_t *p, const uint32_t bitsize);
        void push_back(const string& str_value, const uint32_t bitsize, const uint8_t in_base);
        void clear();
        
        const uint32_t bitsize() const { return end_boffset; }

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
        const BitStream at(const uint32_t bitoffset, const uint32_t bitsize) const;
        uint8_t as_uint8(uint32_t bofs = 0) const { return Integer(at(bofs, min(bofs+8, end_boffset) - bofs)); }
        uint16_t as_uint16(uint32_t bofs = 0) const { return Integer(at(bofs, min(bofs+16, end_boffset) - bofs)); }
        uint32_t as_uint32(uint32_t bofs = 0) const { return Integer(at(bofs, min(bofs+32,end_boffset) - bofs)); }
        uint64_t as_uint64(uint32_t bofs = 0) const { return Integer(at(bofs, min(bofs+64,end_boffset) - bofs)); }
        Integer as_Integer(uint32_t bofs = 0) const { return Integer(at(bofs, end_boffset - bofs)); }

    protected:
        const Integer a2Integer(const uint8_t *input, const int32_t bitsize) const;

    private:
        uint32_t end_boffset;
        vector<uint8_t> vvalue;
};

class ByteStream
{
    public:       
        ByteStream() { vvalue.reserve(32); };
        ByteStream(const ByteStream &b) { vvalue = b.vvalue; }
        ByteStream(const Integer& value, uint32_t size);
        ByteStream(const char *p, uint32_t size) { vvalue.reserve(size); push_back_ptr(reinterpret_cast<const uint8_t*>(p), size); }
        ByteStream(const uint8_t *p, uint32_t size) { vvalue.reserve(size); push_back_ptr(p, size); }
        ByteStream(const string& str_value, const uint32_t size, const uint8_t in_base) { vvalue.reserve(size); push_back(str_value, size, in_base); }
        
        void push_back(const ByteStream &b) { vvalue.insert(vvalue.end(), b.vvalue.begin(), b.vvalue.end()); }
        void push_back(const uint64_t value, const uint32_t size);
        void push_back_ptr(const uint8_t *p, const uint32_t size);
        void push_back(const string& str_value, const uint32_t size, const uint8_t in_base);
        const ByteStream pop_front(const uint32_t size);

        const ByteStream sha256() const;
        const ByteStream keccak256() const;
        const ByteStream address() const;

        friend ostream& operator<<(ostream& out, const ByteStream &v);

        inline void clear() { vvalue.clear(); }
        inline const uint32_t byteSize() const { return vvalue.size(); }

        inline operator uint8_t*() { return reinterpret_cast<uint8_t*>(vvalue.data()); }
        inline operator const unsigned char*() const { return reinterpret_cast<const unsigned char*>(vvalue.data()); }     
        inline operator const Integer() const { return as_Integer(); }

        inline bool operator==(const ByteStream &b) const { return vvalue == b.vvalue; }
        inline bool operator!=(const ByteStream &b) const { return vvalue != b.vvalue; }
        //inline bool operator< (const ByteStream &b) const { return Integer(*this) <  Integer(b); }
        //inline bool operator> (const ByteStream &b) const { return Integer(*this) >  Integer(b); }
        //inline bool operator<=(const ByteStream &b) const { return Integer(*this) <= Integer(b); }
        //inline bool operator>=(const ByteStream &b) const { return Integer(*this) >= Integer(b); }

        //Unaligned operators
        //inline const ByteStream at(const uint32_t offset, const uint32_t size) const { return ByteStream(&vvalue.data()[offset], size); };
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
        //Neutral Constructors (no encoding):
        RLPByteStream() : ByteStream() { }
        RLPByteStream(const RLPByteStream& b) : ByteStream(dynamic_cast<const ByteStream&>(b)) {}
        RLPByteStream(const uint8_t *p, uint32_t size) : ByteStream(p, size) {}
        
        //Contructor can encode or not
        RLPByteStream(const char *str_value, const bool encode = false);

        //Constructor = Empty RLP encoder:
        RLPByteStream(bool as_list) : ByteStream() { push_back((as_list ? 0xC0 : 0x80 ), 1); }
        //Constructor = ByteStream RLP encoder:
        RLPByteStream(const ByteStream &to_rlp_encode) : ByteStream() { fromByteStream(to_rlp_encode); };
        //Constructor = integer RLP encoder:
        RLPByteStream(const uint64_t val, uint32_t size);
        //Constructor = RLP list RLP encoder:
        RLPByteStream(const vector<RLPByteStream>& list_to_rlp_encode);

        //RLP decoder as element
        const ByteStream decode();
        //RLP decoder as list
        const vector<RLPByteStream> decodeList();

        bool isList() const { return byteSize() && as_uint8() >= 0xC0; }

    protected:
        void fromByteStream(const ByteStream &to_rlp_encode);
        void getDataLocation(uint64_t &data_offset, uint64_t &data_size) const;
};

// This function basically removes all separators and spreads the remaining words inside a vector
// The strict sequence (n x "1 word / 1 separator") is not verified (several consecutive separators
// are not interpreted as empty word(s); they are just removed)
vector<string> split(const string& list, const string& separator);

static inline uint32_t log2(const uint32_t x);

static inline uint32_t sizeInBytes(const Integer& value)
{
    uint32_t tmp = value.size_in_base(2);
    return (tmp>>3) + (tmp%8);
}
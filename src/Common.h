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
        void set_from_ptr(const uint8_t *p, const uint32_t bitsize);
        const Integer a2Integer(const uint8_t *input, const int32_t bitsize) const;

    private:
        uint32_t end_boffset;
        vector<uint8_t> vvalue;
};

class ByteStream
{
    public:
        enum class RLP{BYTE, STRING, LIST};
        
        ByteStream();
        ByteStream(const ByteStream& b) { vvalue = b.vvalue; }
        ByteStream(const uint64_t val, uint32_t size) { push_back(val, size); }
        ByteStream(const char *p, uint32_t size) { set_from_ptr(reinterpret_cast<const uint8_t*>(p), size); }
        ByteStream(const uint8_t *p, uint32_t size) { set_from_ptr(p, size); }
        ByteStream(const string& str_value, const uint32_t size, const uint8_t in_base) { push_back(str_value, size, in_base); }
        
        void push_back(const ByteStream& b) { vvalue.insert(vvalue.end(), b.vvalue.begin(), b.vvalue.end()); }
        void push_back(const uint64_t value, uint32_t size);
        void push_back(const string& str_value, const uint32_t size, const uint8_t in_base);
    
        void clear() { vvalue.clear(); }
        
        const uint32_t byteSize() const { return vvalue.size(); }

        const ByteStream sha256() const;
        const ByteStream keccak256() const;
        const ByteStream address() const;

        const vector<ByteStream> rlpListDecode() const;

        friend ostream& operator<<(ostream& out, const ByteStream& v);
        
        operator uint8_t*() { return reinterpret_cast<uint8_t*>(vvalue.data()); }
        operator const unsigned char*() const { return reinterpret_cast<const unsigned char*>(vvalue.data()); }     
        operator const Integer() const { return a2Integer(vvalue.data(), vvalue.size()); }

        inline bool operator==(const ByteStream& b) const { return vvalue == b.vvalue; }
        inline bool operator!=(const ByteStream& b) const { return vvalue != b.vvalue; }
        //inline bool operator< (const ByteStream& b) const { return Integer(*this) <  Integer(b); }
        //inline bool operator> (const ByteStream& b) const { return Integer(*this) >  Integer(b); }
        //inline bool operator<=(const ByteStream& b) const { return Integer(*this) <= Integer(b); }
        //inline bool operator>=(const ByteStream& b) const { return Integer(*this) >= Integer(b); }

        //Unaligned operators
        const ByteStream at(const uint32_t offset, const uint32_t size) const { return ByteStream(&vvalue.data()[offset], size); };
        uint8_t as_uint8() const { return (vvalue.size()>0 ? vvalue[0] : 0); }
        //uint16_t as_uint16(uint32_t ofs = 0) const { return Integer(at(ofs, min(ofs+2, byteSize()) - ofs)); }
        //uint32_t as_uint32(uint32_t bofs = 0) const { return Integer(at(bofs, min(bofs+32,end_boffset) - bofs)); }
        //uint64_t as_uint64(uint32_t bofs = 0) const { return Integer(at(bofs, min(bofs+64,end_boffset) - bofs)); }
        //Integer as_Integer(uint32_t bofs = 0) const { return Integer(at(bofs, end_boffset - bofs)); }

    protected:
        void set_from_ptr(const uint8_t *p, const uint32_t size);
        const Integer a2Integer(const uint8_t *input, const int32_t size) const;

    private:
        vector<uint8_t> vvalue;
};

class RLPByteStream: public ByteStream
{
    public:
        RLPByteStream(const uint64_t val, uint32_t size) { fromByteStream(ByteStream(val, size)); }
        RLPByteStream(const string& str_value, const uint32_t size, const uint8_t in_base) { fromByteStream(ByteStream(str_value, size, in_base)); }

        //Empty RLP constructor
        RLPByteStream(bool as_list = false) { push_back((as_list ? 0xC0 : 0x80 ), 1); }
        //RLP element constructor
        RLPByteStream(const ByteStream& to_rlp_encode) { fromByteStream(to_rlp_encode); };
        //RLP list constructor
        RLPByteStream(const vector<RLPByteStream> list_to_rlp_encode);

    protected:
        void fromByteStream(const ByteStream& to_rlp_encode);
};

// This function basically removes all separators and spreads the remaining words inside a vector
// The strict sequence (n x "1 word / 1 separator") is not verified (several consecutive separators
// are not interpreted as empty word(s); they are just removed)
vector<string> split(const string list, const string separator);

static inline uint32_t log2(const uint32_t x);
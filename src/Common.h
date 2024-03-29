#pragma once

#include <givaro/modular-integer.h>
#include <tools/tools.h>
#include <map>

using std::ostream;
using std::min;
using Givaro::Integer;

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
        ByteStream(const vector<uint8_t> &v) { vvalue = v; }
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

        void resize(const uint32_t size, const uint8_t value = 0) { vvalue.resize(size, value); }

        void push_back(const ByteStream &b) { vvalue.insert(vvalue.end(), b.vvalue.begin(), b.vvalue.end()); }
        void push_back(const uint64_t value, const uint64_t size);
        void push_back_ptr(const uint8_t *p, const uint64_t size);
        void push_back(const string &str_value, const uint64_t size, const uint8_t in_base);

        const void push_front(const ByteStream &b) { vvalue.insert(vvalue.begin(), b.vvalue.begin(), b.vvalue.end()); };
        const void push_front(const uint64_t value, const uint64_t size);
        const ByteStream pop_front(const uint64_t size);

        const ByteStream sha256() const;
        const ByteStream keccak256() const;
        const ByteStream address() const;

        friend ostream& operator<<(ostream &out, const ByteStream &v);

        inline void clear() { vvalue.clear(); }
        inline const uint64_t byteSize() const { return vvalue.size(); }

        inline operator uint8_t*() { return reinterpret_cast<uint8_t*>(vvalue.data()); }
        inline operator const unsigned char*() const { return reinterpret_cast<const unsigned char*>(vvalue.data()); }     
        inline operator const vector<uint8_t>() const { return vvalue; }
        inline operator const Integer() const { return as_Integer(); }
        operator const string() const;  // inline in the .cpp does not compile!?!

        inline bool operator==(const ByteStream &b) const { return vvalue == b.vvalue; }
        inline bool operator!=(const ByteStream &b) const { return vvalue != b.vvalue; }
        inline bool operator< (const ByteStream &b) const { return Integer(*this) <  Integer(b); }
        inline bool operator> (const ByteStream &b) const { return Integer(*this) >  Integer(b); }
        inline bool operator<=(const ByteStream &b) const { return Integer(*this) <= Integer(b); }
        inline bool operator>=(const ByteStream &b) const { return Integer(*this) >= Integer(b); }

        inline const ByteStream at(const uint64_t offset, const uint64_t size) const { return ByteStream(&vvalue[offset], size); };
        inline const uint8_t as_uint8() const { return (byteSize()>0 ? vvalue[0] : 0); }
        const uint64_t as_uint64() const;
        const Integer as_Integer() const { return a2Integer(vvalue.data(), vvalue.size()); }
        const bool as_bool() const { return (as_uint8() ? true : false); }
        
        static const ByteStream generateRandom(const uint32_t size);

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
        RLPByteStream(const vector<uint8_t> &v) : ByteStream(v.data(), v.size()) { }
        RLPByteStream(const RLPByteStream &b) : ByteStream(b) {}
        RLPByteStream(const uint8_t *p, uint64_t size) : ByteStream(p, size) { }
        RLPByteStream(const char *str) : ByteStream(str, strlen(str)>1, 16) { } //for raw RLP init from hex string only
        
        // Encoding constructor:
        // "as_list" is used to:
        //      - discriminates between 0x80 and 0xC0 for an empty input,
        //      - build a list over a single RLP element: this single element 
        //        must have been previously RLP-encoded and is passed as ByteStream,
        //      - rebuild an erased list header (internal use only, by pop_front()),
        RLPByteStream(const ByteStream &to_rlp_encode, const bool as_list = false);

        // Inserts a RLP into an existing RLP
        // NOTA:
        //      - If the rlp param provided is a ByteStream, a call to the RLPByteStream
        //        constructor is made prior to executing the push.
        //      - "at_top_level" used to choose between putting under existing list (false) or
        //        putting at the top level like the existing list (true), thus creating a new top-list header
        void push_back(const RLPByteStream &rlp, const bool at_top_level = false);
        void push_front(const RLPByteStream &rlp, const bool at_top_level = false);

        // Pops the front Element from a serialized RLP
        // NOTA:
        //      - if the poped RLPByteStream is a list, further calls to pop_front on this list
        //        are necessary to reach down the payload,
        //      - if the poped RLPByteStream is a string (non-list), the header is removed
        //        and thus safe to treat as a strict ByteStream payload.
        //      - if is_list = false, it is safe to cast the poped RLPByteStream to a ByteStream
        //        representing the element payload.
        RLPByteStream pop_front(bool &is_list);
};
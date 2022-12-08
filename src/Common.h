#pragma once

#include <givaro/modular-integer.h>

using namespace std;
using namespace Givaro;

Integer a2Integer(const uint8_t* input, const int32_t bitsize);

class Bitstream
{
    public:
        Bitstream();
        Bitstream(const Bitstream&);
        Bitstream(const Integer& val, uint32_t bitsize);
        Bitstream(const char* p, uint32_t bitsize);
        Bitstream(const uint8_t* p, uint32_t bitsize);
        
        void set(const Integer& val, const uint32_t bitsize);
        void push_back(const Integer& bits_value, const uint32_t bitsize);
        void clear();
        
        const uint32_t bitsize() const { return end_boffset; }

        const Bitstream sha256() const;
        const Bitstream keccak256() const;
        const Bitstream address() const;

        friend ostream& operator<<(ostream& out, const Bitstream& v);
        
        operator uint8_t*() { return reinterpret_cast<uint8_t*>(vvalue.data()); }
        operator const unsigned char*() const { return reinterpret_cast<const unsigned char*>(vvalue.data()); }     
        operator const Integer() const { return a2Integer(vvalue.data(), end_boffset); }

        inline bool operator==(const Bitstream& b) const { return Integer(*this) == Integer(b); }
        inline bool operator!=(const Bitstream& b) const { return Integer(*this) != Integer(b); }
        inline bool operator< (const Bitstream& b) const { return Integer(*this) <  Integer(b); }
        inline bool operator> (const Bitstream& b) const { return Integer(*this) >  Integer(b); }
        inline bool operator<=(const Bitstream& b) const { return Integer(*this) <= Integer(b); }
        inline bool operator>=(const Bitstream& b) const { return Integer(*this) >= Integer(b); }

        //Unaligned operators
        const Bitstream at(const uint32_t bitoffset, const uint32_t bitsize) const;
        uint8_t as_uint8(uint32_t bofs = 0) const { return Integer(at(bofs, min(bofs+8,end_boffset) - bofs)); }
        uint16_t as_uint16(uint32_t bofs = 0) const { return Integer(at(bofs, min(bofs+16,end_boffset) - bofs)); }
        uint32_t as_uint32(uint32_t bofs = 0) const { return Integer(at(bofs, min(bofs+32,end_boffset) - bofs)); }
        uint64_t as_uint64(uint32_t bofs = 0) const { return Integer(at(bofs, min(bofs+64,end_boffset) - bofs)); }
        Integer as_Integer(uint32_t bofs = 0) const { return Integer(at(bofs, end_boffset - bofs)); }

    protected:
        void set_from_ptr(const uint8_t* p, const uint32_t bitsize);

    private:
        uint32_t end_boffset;
        vector<uint8_t> vvalue;
};

// This function basically removes all separators and spreads the remaining words inside a vector
// The strict sequence (n x "1 word / 1 separator") is not verified (several consecutive separators
// are not interpreted as empty word(s); they are just removed)
vector<string> split(const string list, const string separator);
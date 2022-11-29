#pragma once

#include <givaro/modular-integer.h>

using namespace std;
using namespace Givaro;

class bitstream
{
    public:
        bitstream(const Integer& val, uint32_t bitsize);
        bitstream(const uint8_t* p, uint32_t bitsize);
        bitstream(const char* p, uint32_t size);
        
        void push_back(const Integer& bits_value, const uint32_t bitsize);
        void clear();
        
        const uint8_t* ptr(uint32_t bytes_offset) const;
        const bitstream at(uint32_t bitoffset, uint32_t bitsize) const;
        const uint32_t bitsize() const { return end_boffset; }

        const bitstream sha256() const;
        const bitstream keccak256() const;
        const bitstream address() const;

        friend ostream& operator<< (ostream& out, const bitstream& v);
        
        operator uint8_t*() { return reinterpret_cast<uint8_t*>(vvalue.data()); }
        operator const uint8_t*() { return reinterpret_cast<const uint8_t*>(vvalue.data()); }
        operator const unsigned char*() const { return reinterpret_cast<const unsigned char*>(vvalue.data()); }      
        operator char*() { return reinterpret_cast<char*>(vvalue.data()); }
        operator const char*() const { return reinterpret_cast<const char*>(vvalue.data()); }
        operator const Integer() const;

    protected:
        const Integer getInteger(const uint8_t* p, int32_t bitsize) const;
        //uint8_t ushort_min(uint8_t a, uint8_t b) {return (a<b?a:b);}

    private:
        uint32_t end_boffset;
        vector<uint8_t> vvalue;
};

string b2a_hex(const uint8_t* p, const size_t n);
string b2a_bin(const uint8_t* p, const size_t n);

template <typename T>
uint8_t* Vector_to_ByteArray(const vector<T>& v, uint8_t* a);

void ByteArray_to_GInteger(const uint8_t* input, Integer& output, const size_t input_size);

void GInteger_to_ByteArray(const Integer& input, uint8_t* output, const size_t output_size);

template <typename T> ostream& operator<< (ostream& out, const vector<T>& v);

// This function basically removes all separators and spreads the remaining words inside a vector
// The strict sequence (n x "1 word / 1 separator") is not verified (several consecutive separators
// are not interpreted as empty word(s); they are just removed)
vector<string> split(const string list, const string separator);
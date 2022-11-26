#pragma once

//#include <givaro/modular-integer.h>
#include <vector>
#include <sstream>
#include <cstring>

using namespace std;
//using namespace Givaro;

/*string b2a_hex(const uint8_t* p, const size_t n) {
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
}*/

template <typename T>
uint8_t* Vector_to_ByteArray(const vector<T>& v, uint8_t* a) {
    memset(a,0xFF,sizeof(T)*v.size());
    typename vector<T>::const_iterator iter;
    for(auto i=0;i<v.size();i++)
        for(auto j=0;j<sizeof(T);j++)
            *(a+i*sizeof(T)+j) = ((v[i]>>((sizeof(T)-j-1)<<3)) & 0xFF);
    return a;
}

/*template <typename T, typename P>
void v2v_unaligned( const vector<T>& input, vector<P>& output,
                    uint32_t element_bit_size, uint32_t element_count, uint32_t first_element_bit_offset = 0)
{
    //the output vector word must be large enough for the specified element size
    assert((sizeof(P)<<3) >= element_bit_size);

    uint8_t vword_bit_size = (sizeof(input[0])<<3);
    uint128_t vword_mask = ~uint128_t(0) >> ((vword_bit_size << 8) - vword_bit_size);    

    uint32_t max_overlap = (element_bit_size > 1 ? 2 + div(element_bit_size - 2, vword_bit_size).quot : 1);
    
    uint8_t sz;
    uint128_t msk;

    for(uint32_t element_rank=0;element_rank<element_count;element_rank++)
    {
        uint64_t element_bit_offset = first_element_bit_offset + element_rank * element_bit_size;

        div_t d = div(element_bit_offset, vword_bit_size);

        // index (bits) of initial vword
        uint32_t idx = d.quot;
        // initial offset (bits) in vword
        uint8_t ofs0 = d.rem;
        // > 0 (bits) => overlaps next vword
        int32_t bit_overflow = ofs0 + element_bit_size - vword_bit_size;
        // >= 0 (bits) if element entirely in initial vword
        uint32_t free_rbits0 = max(-bit_overflow, 0);
          
        msk = (vword_mask >> ofs0) & (vword_mask << free_rbits0);

        P element = (*(input.data()+idx) & msk) >> free_rbits0;
        
        while(bit_overflow > 0)
        {
            idx++;  //next vword

            sz = max(min((int)bit_overflow, (int)vword_bit_size),0);            

            msk = vword_mask & ~(vword_mask >> sz);                                                 

            element <<= sz;
            element += (*(input.data()+idx) & msk) >> (vword_bit_size - sz);
            
            bit_overflow -= sz;  
        }
        output.push_back(element);
    }
}*/

/*void ByteArray_to_GInteger(const uint8_t* input, Integer& output, const size_t input_size) {
    output = 0;
    if(input_size>0)
    {
        output = input[0];
        if(input_size>1)
        {
            int i;
            uint32_t shift = 256;
            for(i=1;i<input_size;i++)
            {
                output *= shift;
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
}*/

template <typename T> int32_t getIndex(const vector<T>& v, const T elem)
{
    int32_t index = -1;
    //elem = "possible";
    auto it = find(v.begin(), v.end(), elem);
    if (it != v.end())
        index = it - v.begin();
    return index;
}

template <typename T> ostream& operator<< (ostream& out, const vector<T>& v) {
    for(auto i: v) out << i;
    return out;
}

static inline uint32_t log2(const uint32_t x) {
  uint32_t y;
  asm ( "\tbsr %1, %0\n"
      : "=r"(y)
      : "r" (x)
  );
  return y;
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
#pragma once

using namespace std;
using namespace Givaro;

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
uint8_t* Vector_to_ByteArray(const vector<T> v, uint8_t* a) {
    memset(a,0xFF,sizeof(T)*v.size());
    typename vector<T>::const_iterator iter;
    for(auto i=0;i<v.size();i++)
        for(auto j=0;j<sizeof(T);j++)
            *(a+i*sizeof(T)+j) = ((v[i]>>((sizeof(T)-j-1)<<3)) & 0xFF);
    return a;
}

template <typename T>
void v2v_unaligned(const vector<T>& input, vector<uint32_t>& output, uint32_t element_bit_size, uint32_t element_count)
{
    uint8_t vword_bit_size = (sizeof(input[0])<<3);
    uint128_t vword_mask = ~uint128_t(0) >> ((vword_bit_size << 8) - vword_bit_size);    

    uint16_t word_mask = 0xFFFF >> (0x10 - element_bit_size);

    uint32_t max_overlap = (element_bit_size > 1 ? 2 + div(element_bit_size - 2, vword_bit_size).quot : 1);
    
    uint8_t sz[max_overlap];
    uint128_t msk[max_overlap];

    for(uint8_t element_rank=0;element_rank<element_count;element_rank++)
    {
        uint16_t word_bit_rank = element_bit_size * element_rank;

        div_t d = div(word_bit_rank, vword_bit_size);

        uint8_t idx0 = d.quot;
        uint8_t ofs0 = d.rem;
        int8_t bit_overflow = ofs0 + element_bit_size - vword_bit_size;
        int8_t free_rbits0 = max(-bit_overflow, 0);

        sz[0] = min(vword_bit_size - ofs0, (int)element_bit_size);
        msk[0] = (vword_mask >> ofs0) & (vword_mask << free_rbits0);  

        uint32_t element = (*(input.data()+idx0) & msk[0]) >> free_rbits0;
        
        for(auto i=1;i<max_overlap;i++)
        {
            sz[i] = max(min((int)bit_overflow, (int)vword_bit_size),0);            

            msk[i] = vword_mask & ~(vword_mask >> sz[i]);                                                 

            element <<= sz[i];
            element += (*(input.data()+idx0+i) & msk[i]) >> (vword_bit_size - sz[i]);

            if(bit_overflow<=0)
                break;                  // no more overlap => end
            else
                bit_overflow -= sz[i];  // => next vword
        }
        output.push_back(element);
    }
}

void ByteArray_to_GInteger(const uint8_t* input, Integer &output, const size_t input_size) {
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

void GInteger_to_ByteArray(const Integer input, uint8_t* output, const size_t output_size) {
    int i;
    Integer last_byte(0xFF);
    for(i=0;i<output_size;i++)
        output[i] = (input >> ((output_size-1-i) << 3)) & last_byte;
}
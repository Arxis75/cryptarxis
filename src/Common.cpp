#include "Common.h"

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
uint8_t* Vector_to_ByteArray(const vector<T>& v, uint8_t* a) {
    memset(a,0xFF,sizeof(T)*v.size());
    typename vector<T>::const_iterator iter;
    for(auto i=0;i<v.size();i++)
        for(auto j=0;j<sizeof(T);j++)
            *(a+i*sizeof(T)+j) = ((v[i]>>((sizeof(T)-j-1)<<3)) & 0xFF);
    return a;
}
template uint8_t* Vector_to_ByteArray<uint32_t>(const vector<uint32_t>& v, uint8_t* a); //for the linker

void ByteArray_to_GInteger(const uint8_t* input, Integer& output, const size_t input_size) {
    output = 0;
    if(input_size>0)
    {
        output = input[0];
        if(input_size>1)
        {
            int i;
            uint16_t shift = 8;
            for(i=1;i<input_size;i++)
            {
                output <<= shift;
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
}

template <typename T> ostream& operator<< (ostream& out, const vector<T>& v) {
    for(auto i: v) out << i;
    return out;
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
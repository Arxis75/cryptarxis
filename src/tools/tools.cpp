#include "tools.h"
#include <givaro/modular-integer.h>

#include <vector>
#include <string>

using std::vector;
using std::string;
using Givaro::Integer;

/*
Base64 translates 24 bits into 4 ASCII characters at a time. First,
3 8-bit bytes are treated as 4 6-bit groups. Those 4 groups are
translated into ASCII characters. That is, each 6-bit number is treated
as an index into the ASCII character array.

If the final set of bits is less 8 or 16 instead of 24, traditional base64
would add a padding character. However, if the length of the data is
known, then padding can be eliminated.

One difference between the "standard" Base64 is two characters are different.
See RFC 4648 for details.
This is how we end up with the Base64 URL encoding.
*/
string base64_url_encode(const string & in)
{
    string out;
    int val =0, valb=-6;
    size_t len = in.length();
    unsigned int i = 0;
    for (i = 0; i < len; i++)
    {
        unsigned char c = in[i];
        val = (val<<8) + c;
        valb += 8;
        while (valb >= 0)
        {
            out.push_back(base64_url_alphabet[(val>>valb)&0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6)
        out.push_back(base64_url_alphabet[((val<<8)>>(valb+8))&0x3F]);
    return out;
}

string base64_url_decode(const string & in)
{
    string out;
    vector<int> T(256, -1);
    unsigned int i;
    for (i =0; i < 64; i++)
        T[base64_url_alphabet[i]] = i;

    int val = 0, valb = -8;
    for (i = 0; i < in.length(); i++)
    {
        unsigned char c = in[i];
        if (T[c] == -1)
            break;
        val = (val<<6) + T[c];
        valb += 6;
        if (valb >= 0)
        {
            out.push_back(char((val>>valb)&0xFF));
            valb -= 8;
        }
    }
    return out;
}

// This function basically removes all separators and spreads the remaining words inside a vector
// The strict sequence (n x "1 word / 1 separator") is not verified (several consecutive separators
// are not interpreted as empty word(s); they are just removed)
vector<string> split(const string& list, const string& separator)
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
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
#include <vector>
#include <string>

using std::vector;
using std::string;

const char base64_url_alphabet[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'
};

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

/*content   = [seq, k, v, ...]
signature = sign(content)
record    = [signature, seq, k, v, ...]
The maximum encoded size of a node record is 300 bytes. Implementations should reject records larger than this size.

[
    signature,              //mandatory
    seq,                    //mandatory
    "id",                   //mandatory
    "v4",                   //mandatory
    "secp256k1",
    compressed secp256k1 public key, 33 bytes
    "ip",
    IPv4 address, 4 bytes
    "udp",
    UDP port, big endian integer
]
The textual form of a node record is the base64 encoding of its RLP representation,
prefixed by enr:. Implementations should use the URL-safe base64 alphabet and omit padding characters.

exemple(
        ip = 127.0.0.1,
        port 30303,
        node_id = 0xa448f24c6d18e575453db13171562b71999873db5b286df957af199ec94617f7
        seq = 1,
        secret = 0xb71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291
        enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8
        ):
[
  signature = 0x7098ad865b00a582051940cb9cf36836572411a47278783077011599ed5cd16b76f2635f4e234738f30813a89eb9137e3e3df5266e3a1f11df72ecf1145ccb9c,
  seq = 01,
  "id",
  "v4",
  "ip",
  7f000001,
  "secp256k1",
  0x03ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138,
  "udp",
  765f,
]*/

#pragma once

#include <givaro/modular-integer.h>

using namespace std;
using namespace Givaro;

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
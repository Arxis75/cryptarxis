//#include "Common.h"
#include "crypto/bips.h"

//using namespace Givaro;
//using namespace BIP39;

int main(int argc, char** argv)
{
    /*//vector<uint8_t> test({0b11111111,0b11100000,0b01000010,0b10101010});
    vector<uint64_t> test({ 0b1010100010011110110001001110100000110010011101010111011101000001,
                            0b0001101000010000010011111011111011001011101111110110101011000110 });
    vector<uint32_t> m;
    //v2v_unaligned(test, m,11,11);
    const vector<uint8_t> test2  = { 0b10101000,
                                    0b10011110,
                                    0b11000100,
                                    0b11101000,
                                    0b00110010,
                                    0b01110101,
                                    0b01110111,
                                    0b01000001,
                                    0b00011010,
                                    0b00010000,
                                    0b01001111,
                                    0b10111110,
                                    0b11001011,
                                    0b10111111,
                                    0b01101010,
                                    0b11000110 };
    m.clear();*/
    //v2v_unaligned(test2, m,11,11);

    //uint16_t msk1 = ;

    //uint16_t msk0 = uint16_t(vword_mask << (msk0_t + ofs0)) >> ofs0;

    //uint16_t msk0 = ((0xFFFF << ofs0) >> (ofs0 + max((vword_bit_size - ofs0 - word_bit_size) , 0))) << max((vword_bit_size - ofs0 - word_bit_size) , 0);

    //uint16_t w = 1;
    //w = (*(test.data()+ idx0) & msk0) >> ofs0;

    //a = new bitset<11>(*(*reinterpret_cast<bitset<11>*>(test))[10] & (bitset<11>)0x7FF);
    //b = new bitset<11>(*reinterpret_cast<bitset<11>*>(test) & 0x7FF);
    //c = new bitset<11>(*reinterpret_cast<bitset<11>*>(test) & 0x7FF);
    
    //cout << hex << a << endl;
    //cout << hex << a[-1] << endl;
    //cout << hex << a[-2] << endl;

    /*mnemonic* mnc = new mnemonic({"diamond","recycle","math","quantum","earn","save","nut","spice","hen","rice","soft","wire",
                                  "artefact","say","twin","drum","rival","live","mask","lens","actress","peasant","abstract","hint"});*/
    
    BIP39::entropy* e = new BIP39::entropy(128);
    e->add_n_bits_of_entropy(0b1010100, 7);
    e->add_n_bits_of_entropy(0b0100111, 7);
    e->add_n_bits_of_entropy(0b1011000, 7);
    e->add_n_bits_of_entropy(0b1001110, 7);
    e->add_n_bits_of_entropy(0b1000001, 7);
    e->add_n_bits_of_entropy(0b1001001, 7);
    e->add_n_bits_of_entropy(0b1101010, 7);
    e->add_n_bits_of_entropy(0b1110111, 7);
    e->add_n_bits_of_entropy(0b0100000, 7);
    e->add_n_bits_of_entropy(0b1000110, 7);
    e->add_n_bits_of_entropy(0b1000010, 7);
    e->add_n_bits_of_entropy(0b0000100, 7);
    e->add_n_bits_of_entropy(0b1111101, 7);
    e->add_n_bits_of_entropy(0b1111011, 7);
    e->add_n_bits_of_entropy(0b0010111, 7);
    e->add_n_bits_of_entropy(0b0111111, 7);
    e->add_n_bits_of_entropy(0b0110101, 7);
    e->add_n_bits_of_entropy(0b0110001, 7);
    e->add_n_bits_of_entropy(0b10, 2);
    e->print();

    uint32_t word;
    e->get_nth_word(0,11,word);
    e->get_nth_word(2,11,word);
    e->get_nth_word(5,25,word);

    //const vector<uint64_t> entropy= { 0b1010100010011110110001001110100000110010011101010111011101000001,
    //                                  0b0001101000010000010011111011111011001011101111110110101011000110 };
    //BIP39::mnemonic* mnc = new BIP39::mnemonic(entropy);
    //mnemonic* mnc = new mnemonic(" possible    WAGE Deliver gossip first party hair antique salute fuel survey miracle  ");
    //mnc->print();

    return 0;
}
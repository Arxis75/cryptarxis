#include "crypto/Common.h"
#include "crypto/bip39_dictionnary.h"

#include <stdio.h>
#include <string.h>
#include <iostream>
#include <sstream>
#include <vector>

int main(int argc, char** argv)
{
    const char* mnc = "diamond recycle math quantum earn save nut spice hen rice soft wire artefact say twin drum rival live mask lens actress peasant abstract hint"; // = mnemonic Cf BIP39
    const char* pwd = "";
    uint8_t bip39_seed[_64_BYTES];
    uint8_t root_chaincode[_32_BYTES];
    uint8_t root_secret[_33_BYTES];
    uint8_t root_pubkey[_COMPRESSED_33_BYTES];
    uint8_t parent_chaincode[_32_BYTES];
    uint8_t parent_secret[_33_BYTES];
    uint8_t child_chaincode[_32_BYTES];
    uint8_t child_secret[_33_BYTES];
    uint8_t child_pubkey[_COMPRESSED_33_BYTES];
    int32_t index = 0;
    bool hardened = true;

    const vector<uint16_t> incomplete_word_index_list = {1348,1969,464,807,699,1284,834,79,1526,751,1749};

    vector<uint16_t> last_word_index_vector;
    find_mnemonic_last_words( incomplete_word_index_list,
                              last_word_index_vector );

    vector<uint16_t>::const_iterator it;
    for(it=last_word_index_vector.begin();it<last_word_index_vector.end();it++)
        cout << "Found Word: '" << Bip39::Dictionary::WordList_english.at(*it) << "', index = " << *it << endl;

    const vector<const char*> incomplete_word_list = {"possible", "wage", "deliver", "gossip", "first", "party", "hair", "antique", "salute", "fuel", "survey"};
    vector<const char*> last_word_vector;
    find_mnemonic_last_words( incomplete_word_list,
                              last_word_vector );

    vector<const char*>::const_iterator str_it;
    for(str_it=last_word_vector.begin();str_it<last_word_vector.end();str_it++)
        cout << "Found Word: '" << *str_it << "'" << endl;
    
    /*const vector<uint64_t> entropy= { 0b1010100010011110110001001110100000110010011101010111011101000001,
                                      0b0001101000010000010011111011111011001011101111110110101011000110 };*/

    const vector<uint8_t> entropy= { 0b10101000,
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
    vector<const char*> mnc_vector;
    
    mnemonic_from_entropy(entropy, mnc_vector);

    cout << mnc_vector << endl;

    ComputeBIP39Seed(mnc, pwd, sizeof(pwd), bip39_seed);

    ComputeBIP32RootKeys(bip39_seed,root_chaincode,root_secret,root_pubkey);

    memcpy(parent_chaincode, root_chaincode, _32_BYTES);
    memcpy(parent_secret, root_secret, _33_BYTES);
    index = 44;
    hardened = true;

    ComputeBIP32ChildKeys( root_chaincode, root_secret,
                           child_chaincode, child_secret, child_pubkey,
                           index, hardened);

    memcpy(parent_chaincode, child_chaincode, _32_BYTES);
    memcpy(parent_secret, child_secret, _33_BYTES);
    index = 60;
    hardened = true;

    ComputeBIP32ChildKeys( parent_chaincode, parent_secret,
                           child_chaincode, child_secret, child_pubkey,
                           index, hardened);

    memcpy(parent_chaincode, child_chaincode, _32_BYTES);
    memcpy(parent_secret, child_secret, _33_BYTES);
    index = 0;
    hardened = true;

    ComputeBIP32ChildKeys( parent_chaincode, parent_secret,
                           child_chaincode, child_secret, child_pubkey,
                           index, hardened);

    memcpy(parent_chaincode, child_chaincode, _32_BYTES);
    memcpy(parent_secret, child_secret, _33_BYTES);
    index = 0;
    hardened = false;

    ComputeBIP32ChildKeys( parent_chaincode, parent_secret,
                           child_chaincode, child_secret, child_pubkey,
                           index, hardened);

    memcpy(parent_chaincode, child_chaincode, _32_BYTES);
    memcpy(parent_secret, child_secret, _33_BYTES);
    index = 0;
    hardened = false;

    ComputeBIP32ChildKeys( parent_chaincode, parent_secret,
                           child_chaincode, child_secret, child_pubkey,
                           index, hardened);

    uint8_t address[_20_BYTES];
    getPublicKey(child_secret, _33_BYTES, child_pubkey, _64_BYTES, address);

    cout << "Public address: 0x" << b2a_hex(address, _20_BYTES) << endl << endl;

    /*vector<uint64_t> a = {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFEFFFFFC2F};
    reverse(a.begin(), a.end());
    Integer b(a);
    cout << hex << b << endl;
    cout << dec << b << endl;
    //my_ss >> decimal;
    //cout << "The Decimal value of 0x3d is: " << decimal;
    //a << hex << "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
    
    // y^2 = x^3 + 7 
    EllipticCurve ecc( Integer("115792089237316195423570985008687907853269984665640564039457584007908834671663"),
                       Integer("0"),
                       Integer("7") );

    ecc.print();

    Point G( Integer("55066263022277343669578718895168534326250603453777594175500187360389116729240"),
             Integer("32670510020758816978083085130507043184471273380659243275938904335757337482424") );

    if (ecc.verifyPoint(G)){
        G.print();
        std::cout << "Point : verified!!!!" << std::endl;
    };

    Point P2;
    ecc._inv(P2,P);
    if (ecc.verifyPoint(P2)){
        P2.print();
        std::cout << "Inverse : verified" << std::endl;
    };

    Point R; 
    R = ecc._double(R, P);
    if (ecc.verifyPoint(R)){
        R.print();
        std::cout << "double : verified" << std::endl;
    };

    Point Rp ;
    Rp = ecc._add(Rp, P , P);
    if (ecc.verifyPoint(Rp)){
        Rp.print();
        std::cout << "add : verified" << std::endl;
    };

    assert(Rp == R);

    Point R;
    R = ecc._scalar(R,G,Integer("81269605435500711044919518739654423770446280888424070350414648410288584414540"));
    if (ecc.verifyPoint(R)){
        R.print();
        cout << "scalar : verified" << endl;
    };

    string x = R.getX(); 
    string y = R.getY();
    string pubkey = x + y;

    cout << "Public Key = " << pubkey << endl;

    hash256 h = keccak256(reinterpret_cast<const uint8_t*>(&pubkey[0]), 64);   //32 + 32 Bytes (octets)

    uint8_t k[32];
    //convert_to_hex_str(&k[0], h.bytes, 32);
    cout << "Keccak256(pubkey) = " <<  k << endl;*/

    return 0;
}
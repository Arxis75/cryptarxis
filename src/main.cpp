#include "crypto/bips.h"
#include "Common.h"

#include <string>

#include <ethash/keccak.hpp>

#include <chrono>
#include <ctime> 

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

using namespace std;

using namespace BIP39;

Integer generate_k(const Integer& x, const Bitstream& data, const EllipticCurve& ecc)
{
    unsigned char *res;
    uint32_t dilen;
    Bitstream V("0x0101010101010101010101010101010101010101010101010101010101010101", 256, 16);
    Bitstream K("0x0000000000000000000000000000000000000000000000000000000000000000", 256, 16);
    Bitstream V_;

    V_ = Bitstream(V);
    V_.push_back(0x00,8);
    V_.push_back(x,256);
    V_.push_back(data, data.bitsize());
    // K = HMAC(K, V || 0x00 || int2octets(x) || bits2octets(h))
    res = HMAC( EVP_sha256(), K, 32, V_, V_.bitsize()>>3, K, &dilen );
    // V = HMAC(K, V)
    res = HMAC( EVP_sha256(), K, 32, V, V.bitsize()>>3, V, &dilen );

    V_ = Bitstream(V);
    V_.push_back(0x01,8);
    V_.push_back(x,256);
    V_.push_back(data, data.bitsize());
    // K = HMAC(K, V || 0x01 || int2octets(x) || bits2octets(h))
    res = HMAC( EVP_sha256(), K, 32, V_, V_.bitsize()>>3, K, &dilen );
    // V = HMAC(K, V)
    res = HMAC( EVP_sha256(), K, 32, V, V.bitsize()>>3, V, &dilen );

    Bitstream k;
    while(true)
    {
        // V = HMAC(K, V)
        res = HMAC( EVP_sha256(), K, 32, V, V.bitsize()>>3, V, &dilen );
        //k ||= V
        k = V;
        if( Integer(k) > 0 && Integer(k) < ecc.getCurveOrder())
            break;
        
        V_ = Bitstream(V);
        V_.push_back(0x00,8);
        // K = HMAC(K, V || 0x00)
        res = HMAC( EVP_sha256(), K, 32, V_, V_.bitsize()>>3, K, &dilen );
        // V = HMAC(K, V)
        res = HMAC( EVP_sha256(), K, 32, V, V.bitsize()>>3, V, &dilen );
    }

    return k;
}

int main(int argc, char** argv)
{
    EllipticCurve ecc = Secp256r1::GetInstance();
    Integer p = ecc.getFieldOrder();
    Integer n = ecc.getCurveOrder();

    Privkey x(Integer(Bitstream("0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721", 256, 16)), ecc);
    cout << hex << "x = 0x" << x << endl;
    Pubkey U = x.getPubKey();
    cout << hex << "U = (0x" << U.getPoint().getX() << ", 0x" << U.getPoint().getY() << ")" << endl;

    const char* message = "sample";
    cout << "message = " << message << endl;
    Bitstream t_raw(message,strlen(message)<<3);
    Bitstream t_h(t_raw.sha256());
    cout << "message sha256: h = 0x" << t_h << endl;

    Integer k = generate_k(x, t_h, ecc);
    cout << hex << "k = 0x" << k << endl;
    Integer k_1; 
    inv(k_1, k, n);
    cout << hex << "k^(-1) = 0x" << k_1 << endl;
    Point R = ecc.p_scalar(ecc.getGenerator(), k);
    bool parity = !isOdd(R.getY());
    //cout << hex << "R = (0x" << R.getX() << ", 0x" << R.getY() << ")" << endl;
    Integer r = R.getX() % n;
    cout << hex << "r = 0x" << r << endl;
    Integer s = (k_1 * (Integer(t_h) + (r*x))) % n;
    cout << hex << "s = k^(-1) . (h + r.x) = 0x" << s << endl;

    //With SHA-256, message = "sample":
    // k = A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60
    // r = EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716
    // s = F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8

    //keccak256(0x02 || rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, destination, amount, data, access_list]))
    
    /*Bitstream t_raw("0x02ef050784773594008502540be400825208941dcf117c651e34c9e0e397b271bc59477b0fd0fa87038d7ea4c6800080c0", 49<<3, 16);
    Bitstream t_h(t_raw.keccak256());
    
    Bitstream t_from("0x241a383244C822dfDaa3FAb5dBF5127Cd03A773f", 20<<3, 16);
    
    Bitstream t_y_parity("0x01", 1<<3, 16);
    Bitstream t_r("0x70d792a4cb7568ecee34f03b1c271a721aa9b75c78c8f4871c2f256a588148e3", 32<<3, 16);
    Bitstream t_s("0x503bcb74c5b6eff009436c1b262e8640d509a5b09691482c999ba80733cc18c2", 32<<3, 16);
    
    Signature sig(t_r, t_s, !isOdd(t_y_parity));
    Pubkey key;
    if( sig.ecrecover(key, t_h, t_from) )
    {
        cout << endl << "YAY! address 0x" << key.getAddress() << " verified!" << endl << endl;
        return 0;
    }

    bool found = false;
    Integer p = 211;    
    while(!found)
    {
        while(!isPrimeNumber(p)) p++;
        if( (p % 4 == 3) && (1323 % p != 0) )  // for fast sqrtmod && 1323 = 4.A³ + 27.B² != 0
        {
            EllipticCurve ecc = EllipticCurve(p, 0, 7);
            ecc.print_cyclic_subgroups();
            cout << endl;
        }
        p++;
        found = true;
    }*/

    uint8_t toto[97] = { 0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,
                         0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,
                         0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,
                         0b10100000 };
    Bitstream a(&toto[2],10);
    Bitstream c;
    //cout << hex << Integer(a) << endl;
    cout << hex << c << endl;

    Bitstream d(77,8);
    cout << d.sha256() << endl;
    cout << d.keccak256() << endl;
    cout << d.address() << endl;

    Bitstream b("toto",sizeof("toto"));
    //cout << hex << Integer(a) << endl;
    cout << hex << b << endl;

    Mnemonic* mnc = new Mnemonic(128);
    //Mnemonic* mnc = new Mnemonic(160);
    //Mnemonic* mnc = new Mnemonic(192);
    //Mnemonic* mnc = new Mnemonic(224);
    //Mnemonic* mnc = new Mnemonic(256);

    string single_word = "zoo";
    //abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon trouble
    mnc->add_word(single_word);
    mnc->add_word(single_word);
    mnc->add_word(single_word);
    mnc->add_word(single_word);
    mnc->add_word(single_word);
    mnc->add_word(single_word);
    mnc->add_word(single_word);
    mnc->add_word(single_word);
    mnc->add_word(single_word);
    mnc->add_word(single_word);
    mnc->add_word(single_word);
    if(mnc->getEntropySize()>128)
    {
        mnc->add_word(single_word);
        mnc->add_word(single_word);
        mnc->add_word(single_word);
        if(mnc->getEntropySize()>160)
        {
            mnc->add_word(single_word);
            mnc->add_word(single_word);
            mnc->add_word(single_word);
            if(mnc->getEntropySize()>192)
            {
                mnc->add_word(single_word);
                mnc->add_word(single_word);
                mnc->add_word(single_word);
                if(mnc->getEntropySize()>224)
                {
                    mnc->add_word(single_word);
                    mnc->add_word(single_word);
                    mnc->add_word(single_word);
                }
            }
        }
    }

    vector<string> v;
    mnc->list_possible_last_word(v);
    //11 x abandon: about actual age alpha angle argue artwork attract bachelor bean behind blind bomb brand broken burger cactus carbon cereal cheese city click coach cool coyote cricket cruise cute degree describe diesel disagree donor drama dune edit enemy energy escape exhaust express fashion field fiscal flavor food fringe furnace genius glue goddess grocery hand high holiday huge illness inform insect jacket kangaroo knock lamp lemon length lobster lyrics marble mass member metal moment mouse near noise obey offer once organ own parent phrase pill pole position process project question rail record remind render return ritual rubber sand scout sell share shoot simple slice soap solid speed square stereo street sugar surprise tank tent they toddler tongue trade truly turtle umbrella urge vast vendor void voyage wear wife world wrap
    //14 x abandon: address amateur angle around bamboo bleak boil butter cat census clip conduct course cry deer device divorce dune enhance estate face fee float gain general gorilla hedgehog horse inherit item jungle lazy length mansion matrix mix mountain oak one over pear plate pride prosper raw require ride save seed share similar soap spend stamp super tank thumb toward true urge veteran warfare wedding word
    //17 x abandon: agent author biology board camera choose dad desert electric entire fantasy flat grid hundred inherit lemon magic minimum movie one pony push response road school sorry strong task thrive unknown virus wedding
    //20 x abandon: admit breeze choose depart elegant fury hundred infant link mother plastic radar slab sure truck verify
    //23 x abandon: art diesel false kite organ ready surface trouble
    for(int i=0;i<v.size();i++) cout <<  v[i] << endl;
    
    mnc->add_word("trouble");
    mnc->print();

    cout << hex << ecc.getCurveOrder() << endl;
    cout << dec << ecc.getCurveOrder().size_in_base(2) << endl;
    Privkey m(mnc->get_seed("LEDGER"), ecc);
    Privkey m_h44(m,44,true);
    Privkey m_h44_h60(m_h44,60,true);
    Privkey m_h44_h60_h0(m_h44_h60,0,true);
    Privkey m_h44_h60_h0_0(m_h44_h60_h0,0,false);
    int32_t _x = 3;
    Privkey m_h44_h60_h0_0_x(m_h44_h60_h0_0,_x,false);

    cout << "Address: " << hex << m_h44_h60_h0_0_x.getPubKey().getAddress() << endl << endl;;

    delete mnc;

    return 0;
}
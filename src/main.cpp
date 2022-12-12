#include "crypto/bips.h"
#include "Common.h"

#include <string>

#include <ethash/keccak.hpp>

#include <chrono>
#include <ctime> 

using namespace std;

using namespace BIP39;

int main(int argc, char** argv)
{
    //keccak256(0x02 || rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, destination, amount, data, access_list]))
    
    Bitstream t_raw("0x02ef050784773594008502540be400825208941dcf117c651e34c9e0e397b271bc59477b0fd0fa87038d7ea4c6800080c0", 49<<3, 16);
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
    }

    EllipticCurve ecc = Secp256k1::GetInstance();
    p = ecc.getFieldOrder();
    Integer n = ecc.getCurveOrder();

    //p = 211;
    //Integer n(199);
    //EllipticCurve ecc = EllipticCurve(p, 0, 7, Point(12,70), n);

    Integer k = 22;
    cout << hex << "k = 0x" << k << endl;
    Integer k_1; 
    inv(k_1, k, n);
    cout << hex << "k^(-1) = 0x" << k_1 << endl;
    const char* msg = "Hello World!";
    Bitstream h = Bitstream(msg, strlen(msg)<<3).keccak256();
    //Bitstream h(pow(Integer(2),256) - 1, 256);  // for testing purpose
    cout << "message hash = 0x" << h << endl;
    Point R = ecc.p_scalar(ecc.getGenerator(), k);
    bool parity = !isOdd(R.getY());
    cout << hex << "R = (0x" << R.getX() << ", 0x" << R.getY() << ")" << endl;
    Integer r = R.getX() % n;
    cout << hex << "r = 0x" << r << endl;
    Privkey secret(69, ecc);
    cout << hex << "secret = 0x" << secret << endl;
    Pubkey Q = secret.getPubKey();
    cout << hex << "Q = (0x" << Q.getPoint().getX() << ", 0x" << Q.getPoint().getY() << ")" << endl;
    cout << hex << "Address(Q) = 0x" << Q.getAddress() << endl;
    Integer s = (k_1 * (Integer(h) + (r*secret))) % n;
    cout << hex << "s = k^(-1) . (h + r.secret) = 0x" << s << endl;

    /*Signature sig(r, s, parity, ecc);
    Pubkey key;
    if( sig.ecrecover(key, h, Q.getAddress()) )
    {
        cout << endl << "YAY! address 0x" << key.getAddress() << " verified!" << endl;
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
    int32_t x = 3;
    Privkey m_h44_h60_h0_0_x(m_h44_h60_h0_0,x,false);

    cout << "Address: " << hex << m_h44_h60_h0_0_x.getPubKey().getAddress() << endl << endl;;

    delete mnc;

    return 0;
}
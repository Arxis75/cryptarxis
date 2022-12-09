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

    Signature sig(r, s, parity, ecc);
    Pubkey key;
    if( sig.ecrecover(key, h, Q.getAddress()) )
    {
        cout << endl << "YAY! address 0x" << key.getAddress() << " verified!" << endl;
    }

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

    Mnemonic* mnc = new Mnemonic(256);

    const char* xx = "bonjour";
    // diamond recycle math quantum earn save nut spice hen rice soft wire artefact say twin drum rival live mask lens actress peasant abstract hint
    mnc->add_word("diamond");
    mnc->add_word("recycle");
    mnc->add_word("math");
    mnc->add_word("quantum");
    mnc->add_word("earn");
    mnc->add_word("save");
    mnc->add_word("nut");
    mnc->add_word("spice");
    mnc->add_word("hen");
    mnc->add_word("rice");
    mnc->add_word("soft");
    mnc->add_word("wire");
    mnc->add_word("artefact");
    mnc->add_word("say");
    mnc->add_word("twin");
    mnc->add_word("drum");
    mnc->add_word("rival");
    mnc->add_word("live");
    mnc->add_word("mask");
    mnc->add_word("lens");
    mnc->add_word("actress");
    mnc->add_word("peasant");
    mnc->add_word("abstract");
    
    vector<string> v;
    mnc->list_possible_last_word(v);
    for(int i=0;i<v.size();i++) cout <<  v[i] << endl;
    
    mnc->add_word("hint");
    mnc->print();

    cout << hex << ecc.getCurveOrder() << endl;
    cout << dec << ecc.getCurveOrder().size_in_base(2) << endl;
    Privkey m(mnc->get_seed("toto"), ecc);
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
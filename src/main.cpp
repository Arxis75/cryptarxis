#include "crypto/bips.h"
#include "Common.h"

#include <string>

#include <ethash/keccak.hpp>

#include <chrono>
#include <ctime> 

using namespace std;

using namespace BIP39;
using namespace BIP32;

int main(int argc, char** argv)
{
    Integer p;

    bool found = false;
    p = 211;
    cout << "p % 4 = " << 211 % 4 << endl << endl;
    
    while(!found)
    {
        while(!isPrimeNumber(p)) p++;
        if( (p % 4 == 3) && (1323 % p != 0) )  // 4.A³ + 27.B² != 0
        {
            EllipticCurve ecc = EllipticCurve(p, 0, 7);
            for(Integer x=0;x<p;x++)
            {
                Element y2 = ecc.getY2(x);
                for(Integer y=0;y<p;y++)
                {   
                    Element y2_candidat = y*y % p;
                    if( y2_candidat == y2)
                    {
                        cout << "G(" << dec << x << "," << y << ")" << " solution of y²=x³+7 [" << p << "]" << endl;
                        Integer k=1;
                        int count = 0;
                        for(k=1;k<=p;k++)
                        {
                            Point G(x,y);
                            Point R = ecc.p_scalar(G,k);
                            if( R.isIdentity() )
                            {
                                count++;
                                cout << "Point at Infinity";
                                break;
                            }
                            cout << "("<< dec << R.getX() << "," << R.getY() << ") ";
                            count++;
                        }
                        cout << endl;
                        if(isPrimeNumber(count)) cout << "Curve Order is Prime! n = " << dec << count;
                        cout << endl << endl;
                    }
                }
            }
        }
        p++;
        found = true;
    }


    //EllipticCurve ecc = Secp256k1::GetInstance();
    //Integer p = ecc.getFieldOrder();
    //Integer n = ecc.getCurveOrder();

    p = 211;
    Integer n(199);
    EllipticCurve ecc = EllipticCurve(p, 0, 7, Point(12,70), n);

    Integer k = 22;
    //cout << hex << "k = 0x" << k << endl;
    Integer k_1; 
    inv(k_1, k, n);
    //cout << hex << "k^(-1) = 0x" << k_1 << endl;
    const char* m = "Hello World!";
    bitstream h = bitstream(m, strlen(m)<<3).keccak256();
    //bitstream h(pow(Integer(2),256) - 1, 256);  // for testing purpose
    //cout << "message hash = 0x" << h << endl;
    Point R = ecc.p_scalar(ecc.getGenerator(), k);
    bool parity = !isOdd(R.getY());
    //cout << hex << "R = (0x" << R.getX() << ", 0x" << R.getY() << ")" << endl;
    Integer r = R.getX() % n;
    //cout << hex << "r = 0x" << r << endl;
    Integer privKey = 69;
    //cout << hex << "privKey = 0x" << privKey << endl;
    pubkey Q = ecc.p_scalar(ecc.getGenerator(), privKey);
    //cout << hex << "Q = (0x" << Q.getX() << ", 0x" << Q.getY() << ")" << endl;
    cout << hex << "Address(Q) = 0x" << Q.getAddress() << endl;
    Integer s = (k_1 * (Integer(h) + (r*privKey))) % n;
    //cout << hex << "s = k^(-1) . (h + r.privKey) = 0x" << s << endl;

    Point Q_candidate;
    if( ecc.ecrecover(Q_candidate, h, r, s, parity, Q.getAddress()) )
    {
        cout << endl << "YAY!" << endl << endl;
        pubkey key(Q_candidate);
    }

    uint8_t toto[97] = { 0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,
                         0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,
                         0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,
                         0b10100000 };
    bitstream a(&toto[2],10);
    bitstream c;
    //cout << hex << Integer(a) << endl;
    cout << hex << c << endl;

    bitstream d(77,8);
    cout << d.sha256() << endl;
    cout << d.keccak256() << endl;
    cout << d.address() << endl;

    bitstream b("toto",sizeof("toto"));
    //cout << hex << Integer(a) << endl;
    cout << hex << b << endl;

    mnemonic* mnc = new mnemonic(256);

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

    /*extprivkey m(mnc->get_seed("toto"));
    extprivkey m_h44(m,44,true);
    extprivkey m_h44_h60(m_h44,60,true);
    extprivkey m_h44_h60_h0(m_h44_h60,0,true);
    extprivkey m_h44_h60_h0_0(m_h44_h60_h0,0,false);
    int32_t x = 3;
    extprivkey m_h44_h60_h0_0_x(m_h44_h60_h0_0,x,false);

    cout << "Address: " << hex << m_h44_h60_h0_0_x.getExtPubKey().getAddress() << endl << endl;;

    delete mnc;*/

    return 0;
}
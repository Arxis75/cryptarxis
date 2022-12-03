#include "crypto/bips.h"
#include "Common.h"

#include <string>

#include <ethash/keccak.hpp>

using namespace std;

using namespace BIP39;
using namespace BIP32;

// Function that checks whether n is prime or not
bool isPrimeNumber(int n) {
   bool isPrime = true;

   for(int i = 2; i <= n/2; i++) {
      if (n%i == 0) {
         isPrime = false;
         break;
      }
   }  
   return isPrime;
}

Integer power(Integer x, Integer y, Integer p)
{
    Integer res = 1;     // Initialize result
 
    x = x % p; // Update x if it is more than or
                // equal to p
  
    if (x == 0) return 0; // In case x is divisible by p;
 
    while (y > 0)
    {
        // If y is odd, multiply x with result
        if (y & Integer(1))
            res = (res*x) % p;
 
        // y must be even now
        y = y>>1; // y = y/2
        x = (x*x) % p;
    }
    return res;
}

int main(int argc, char** argv)
{
    /*bool found = false;
    Integer p = 211;
    while(!found)
    {
        while(!isPrimeNumber(p)) p++;
        EllipticCurve ecc = EllipticCurve(p, 0, 7);
        if( !ecc.curve->isZeroDiscriminant() )
            for(Integer x=0;x<p;x++)
            {
                Element y2;
                ecc.FField->mul(y2,x,x);
                ecc.FField->mul(y2,y2,x);
                ecc.FField->add(y2,y2,7);
                for(Integer y=0;y<p;y++)
                {   
                    Element y2_candidat;
                    ecc.FField->mul(y2_candidat,y,y);
                    if( y2_candidat == y2)
                    {
                        cout << "G(" << dec << x << "," << y << ")" << " solution of y²=x³+7 [" << p << "]" << endl;
                        Integer k=1;
                        int count = 0;
                        for(k=1;k<=p;k++)
                        {
                            Point G(x,y);
                            Point R;
                            ecc._scalar(R,G,k);
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
        p++;
    }*/

    Integer p(211);
    Integer n(199);
    EllipticCurve ecc = EllipticCurve(p, 0, 7);
    Point G(12,70);

    Integer k = 22;

    Integer k_1 = power(k, n-2, n) % n;  //Little Fermat theorem
    cout << dec << k_1 << endl;

    bitstream m("Hello World!", 12<<3);
    Integer h = Integer(m.keccak256()) % n;
    //h += n;

    Point R;
    ecc._scalar(R,G,k);
    Integer r = R.getX() % n;
    //r += n;

    Integer privKey = 44;

    Integer s = (k_1 * (h + r*privKey)) % n;
    cout << dec << s << endl;

    Integer r_1 = power(r, n-2, n) % n;  //Little Fermat theorem
    cout << dec << r_1 << endl;

    Integer pubKey = (r_1 * (s + r*privKey)) % n;


    /*Point R = Secp256k1::GetInstance().getGenerator();
    Integer k=0;
    while( R.getX()< Secp256k1::GetInstance().getCurveOrder() )
    {
        k++;
        R = Secp256k1::GetInstance().Gmul(k);
        cout << hex << R.getX() << " / " << dec << k << endl;
    }
    cout << "k found!! = " << hex << k << endl;*/

    uint8_t toto[97] = { 0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,
                         0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,
                         0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,0xFF,0,0,0xFF,
                         0b10100000 };
    bitstream a(&toto[2],10);
    bitstream c(a.at(2,3));
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
    int y = sizeof(xx);
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
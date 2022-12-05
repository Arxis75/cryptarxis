#include "crypto/bips.h"
#include "Common.h"

#include <string>

#include <ethash/keccak.hpp>

#include <chrono>
#include <ctime> 

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

bool sqrtmod(Integer& root, const Integer& n, const Integer& mod, const bool parity)
{
    assert(mod%4 == 3);
    root = powmod(n, (mod+1)>>2, mod);
    if( parity == isOdd(root) )
        root = mod - root;
    bool ret = (powmod(root, 2, mod) == n);
    if(!ret)
        root = 0;
    return ret;
}

bool ecrecover( pubkey& key,
                const bitstream& msg_hash, const Integer& r, const Integer& s, const bool parity,
                const bitstream& from_address )
{
    const EllipticCurve ecc = Secp256k1::GetInstance();
    Point G = ecc.getGenerator();
    Integer p = ecc.getFieldOrder();
    Integer n = ecc.getCurveOrder();

    assert(msg_hash.bitsize() == 256);
    assert(r < n);
    assert(s < n);
    assert(from_address.bitsize() == 160);

    bool ret = false;
    Integer r_candidate = r;
    while(!ret && r_candidate < p)
    {
        Integer y;
        if( sqrtmod(y, (r_candidate*r_candidate*r_candidate+7)%p, p, parity) )
        {
            Point sR;
            Point R = Point(r_candidate, y);
            ecc._scalar(sR,R,s);
            Point hG;
            ecc._scalar(hG,G,msg_hash);
            Point _hG;
            ecc._inv(_hG,hG);
            Point sR_hG;
            ecc._add(sR_hG,sR,_hG);
            Integer r_1;
            inv(r_1, r, n);
            pubkey Q_candidate(G);
            ecc._scalar(Q_candidate,sR_hG,r_1);
            ret = (Q_candidate.getAddress() == from_address);
        }
        r += n;
    }
    return ret;
}

int main(int argc, char** argv)
{
    bool found = false;
    Integer p = 211;
    cout << Secp256k1::GetInstance().getFieldOrder() % 4 << endl;
    cout << 211 % 4 << endl;
    
    /*while(!found)
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
        found = true;
    }*/

    p = 211;
    EllipticCurve ecc = EllipticCurve(p, 0, 7);
    Point G(12,70);
    Integer n(199);

    Integer k = 22;
    cout << dec << "k = " << k << endl;
    Integer k_1; 
    //k_1 = powmod(k,n-2,n);
    //cout << dec << k_1 << endl;
    inv(k_1, k, n);
    cout << dec << "k^(-1) = " << k_1 << endl;

    const char* m = "Hello World!";
    Integer h = Integer(bitstream(m, strlen(m)<<3).keccak256()) % n;
    //h += n;
    cout << dec << "h = " << h << endl;

    Point R;
    ecc._scalar(R,G,k);
    bool parity = !isOdd(R.getY());
    cout << dec << "R = (" << R.getX() << "," << R.getY() << ")" << endl;
    Integer r = R.getX() % n;
    //r += n;
    cout << dec << "r = " << r << endl;

    Integer privKey = 69;
    cout << dec << "privKey = " << privKey << endl;
    pubkey Q(G);
    ecc._scalar(Q,G,privKey);
    cout << dec << "Q = (" << Q.getX() << "," << Q.getY() << ")" << endl;
    cout << dec << "Address(Q) = 0x" << Q.getAddress() << endl;
    

    Integer s = (k_1 * (h + (r*privKey))) % n;
    cout << dec << "s = k^(-1) . (h + r.privKey) = " << s << endl;
    //cout << dec << "s . k = h + r.privKey" << endl;
    //cout << dec << "s . kG = hG + r.privKeyG" << endl;
    //cout << dec << "sR - hG = r.Q " << endl;
    //cout << dec << "Q = r^(-1) . (sR - hG)" << endl;

    //cout << dec << "s . k = " << (s*k)%n << endl;
    //cout << dec << "h + r.privKey = " << (h+r*privKey)%n << endl;

    //Point skG;
    //ecc._scalar(skG,G,(s*k)%n);
    //cout << dec << "skG = (" << skG.getX() << "," << skG.getY() << ")" << endl;

    Integer r_candidate = r+n;
    Integer y;
    if( sqrtmod(y, (r_candidate*r_candidate*r_candidate+7)%p, p, parity) )
    {
        Point sR;
        R = Point(r_candidate, y);
        //cout << dec << "R_candidate = (" << R.getX() << "," << R.getY() << ")" << endl;
        ecc._scalar(sR,R,s);
        //cout << dec << "sR = (" << sR.getX() << "," << sR.getY() << ")" << endl;

        Point hG, rprivKeyG;
        ecc._scalar(hG,G,h);
        //cout << dec << "hG = (" << hG.getX() << "," << hG.getY() << ")" << endl;

        //ecc._scalar(rprivKeyG,G,(r*privKey)%n);
        //cout << dec << "rprivKeyG = (" << rprivKeyG.getX() << "," << rprivKeyG.getY() << ")" << endl;

        Point _hG;
        ecc._inv(_hG,hG);
        //cout << dec << "_hG = (" << _hG.getX() << "," << _hG.getY() << ")" << endl;

        //Point skG_hG;
        //ecc._add(skG_hG,skG,_hG);
        //cout << dec << "skG_hG = (" << skG_hG.getX() << "," << skG_hG.getY() << ")" << endl;

        Point sR_hG;
        ecc._add(sR_hG,sR,_hG);
        //cout << dec << "sR_hG = (" << sR_hG.getX() << "," << sR_hG.getY() << ")" << endl;

        Integer r_1;
        inv(r_1, r, n);
        //cout << dec << "r^(-1) = " << r_1 << endl;

        pubkey Q_candidate(G);
        ecc._scalar(Q_candidate,sR_hG,r_1);
        cout << dec << "Q_candidate = (" << Q_candidate.getX() << "," << Q_candidate.getY() << ")" << endl;
        cout << dec << "Address(Q_candidate) = 0x" << Q_candidate.getAddress() << endl;
    }

    /*Integer r_1;
    inv(r_1, r, n);
    cout << dec << "r^(-1) = " << r_1 << endl;
    Integer y_candidate;
    if( sqrtmod(y_candidate, (powmod(r+n,3,p)+7)%p, 211, parity) )
    {
        R = Point(r, y_candidate);
        cout << dec << "Rcandidate = (" << r+n << "," << y_candidate << ")" << endl;

        Point sR;
        ecc._scalar(sR,R,s);
        Point hG;
        ecc._scalar(hG,G,h);
        Point sR_hG;
        Point tmp;
        ecc._add(tmp,sR, hG);
        ecc._inv(sR_hG, tmp);
        Point candidate_Q;
        ecc._scalar(candidate_Q, sR_hG, r_1);
        cout << dec << "candidate pubKey Q = (" << candidate_Q.getX() << "," << candidate_Q.getY() << ")" << endl;
    }
    else
    {
        cout << "Signature: r is invalid!";
    }*/


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
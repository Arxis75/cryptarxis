#include "crypto/bips.h"
#include "Common.h"

#include <string>

using namespace std;

using namespace BIP39;

int main(int argc, char **argv)
{
    Mnemonic mnc(128);
    if(mnc.set_full_word_list("physical eagle dry banana embrace aisle virtual spell modify series doctor tonight"))
    {
        Privkey x(mnc, "m/44'/60'/0'/0/0");
        x.print();
        
        //keccak256(0x02 || rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, destination, amount, data, access_list]))

        // SIGNING PAYLOAD:
        // transaction_type:                       0x02    (EIP1559)
        // RLP list/size:              0xc0+0x2F       = 7 Bytes RLP headers + 40(0x28) Bytes RLP payload      <= 55 Bytes
        // chain_id:                               0x05            (GOERLI)
        // // nonce:                                  0x07
        // max_priority_fee_per_gas:   0x80+0x04/  0x77359400      ( 2E+09 =  2 GWEI)
        // max_fee_per_gas:            0x80+0x05/  0x02540be400    (10E+09 = 10 GWEI)
        // gas_limit:                  0x80+0x02/  0x5208              ( = 21000 WEI)
        // to:                         0x80+0x14/  0x1dcf117c651e34c9e0e397b271bc59477b0fd0fa
        // eth:                        0x80+0x07/  0x038d7ea4c68000    (0.001E+18 = 0.001 ETH)
        // data:                       0x80
        // access_list:                0xc0

        Bitstream t_raw("0x02ef050784773594008502540be400825208941dcf117c651e34c9e0e397b271bc59477b0fd0fa87038d7ea4c6800080c0", 49<<3, 16);
        Bitstream t_h(t_raw.keccak256());

        Signature sig = x.sign(t_h, true);
        sig.print();
    }

    /*Signature actual_sig = x.sign(t_h);
    cout << hex << "my signature_y_parity = " << (actual_sig.get_imparity() ? "impair" : "pair") << endl;
    cout << hex << "my r = " << actual_sig.get_r() << endl;
    cout << hex << "my s = " << actual_sig.get_s() << endl;

    if( actual_sig.ecrecover(key, t_h, t_from) )
    {
        cout << endl << "YAY! address 0x" << key.getAddress() << " verified!" << endl << endl;
    }
  
    bool t_y_imparity = 0x01;
    Bitstream t_r("0x70d792a4cb7568ecee34f03b1c271a721aa9b75c78c8f4871c2f256a588148e3", 32<<3, 16);
    Bitstream t_s("0x503bcb74c5b6eff009436c1b262e8640d509a5b09691482c999ba80733cc18c2", 32<<3, 16);

    Signature sig(t_r, t_s, t_y_imparity);
    if( sig.ecrecover(key, t_h, t_from) )
    {
        cout << endl << "YAY! address 0x" << key.getAddress() << " verified!" << endl << endl;
    }*/

    /*Integer sk = Integer(t_h) + Integer(Bitstream("0x70d792a4cb7568ecee34f03b1c271a721aa9b75c78c8f4871c2f256a588148e3", 256, 16)) * x.getSecret();
    sk %= n;
    cout << sk << endl;
    Integer my_sk = (actual_sig.get_s() * Bitstream("0xd961afcbb57eba843b8e7fbc5b5840d5158f503530184df09665c1665f031e9e", 256, 16));
    my_sk %= n;
    cout << my_sk << endl;
    Integer their_sk = (Integer(t_s) * Bitstream("0xd961afcbb57eba843b8e7fbc5b5840d5158f503530184df09665c1665f031e9e", 256, 16));
    their_sk %= n;
    cout << their_sk << endl;*/

    /*//EllipticCurve ecc = Secp256k1::GetInstance();
    Integer p = 211;
    Point G(12,70);
    Integer n = 199;
    EllipticCurve ecc = EllipticCurve(p, 0, 7, G, n);

    Integer x_candidate = 24; 
    Privkey x(Bitstream(x_candidate, 8), Privkey::Format::SCALAR, ecc);

    const char *msg = "hello";
    Bitstream msg_raw(msg,strlen(msg)<<3);
    Bitstream msg_h(msg_raw.keccak256());
    
    Signature sig = x.sign(msg_h, true);

    Pubkey Q;
    sig = Signature(3, 102, true, ecc);
    if( sig.isValid(msg_h, x.getPubKey().getAddress(), false) )
        if( sig.ecrecover(Q,msg_h,x.getPubKey().getAddress()) )
            cout << "Pre EIP-2 Sig recovered!" << endl;

    sig = Signature(3, 97, false, ecc);
    if( sig.isValid(msg_h, x.getPubKey().getAddress(), true) )
        if( sig.ecrecover(Q, msg_h,x.getPubKey().getAddress()) )
            cout << "Post EIP-2 Sig recovered!" << endl;
        
    int tototo = 1;*/

    // R(0x1, 0x4218f20ae6c646b363db68605822fb14264ca8d2587fdd6fbc750d587e76a7ee)
    /*Point R(Integer("1"), Integer("29896722852569046015560700294576055776214335159245303116488692907525646231534"));

    if(ecc.verifyPoint(R))
    {
        Point O = ecc.p_scalar(R, ecc.getGeneratorOrder());
        if(O.isIdentity())
        {
            const char *message = "hello";
            Bitstream t_raw(message,strlen(message)<<3);
            Bitstream t_h(t_raw.keccak256());
            cout << hex << t_h << endl;

            //Point Q = ecc.p_add(R, ecc.p_inv(ecc.p_scalar(ecc.getGenerator(), t_h)));
            //cout << hex << Q.getX() << ", " << Q.getY() << endl;

            Pubkey Qrec;
            Signature sig(1, 1, false);
            sig.ecrecover(Qrec, t_h);
            cout << hex << Qrec.getPoint().getX() << ", " << Qrec.getPoint().getY() << endl;

            if(ecc.verifyPoint(Qrec.getPoint()))
            {
                O = ecc.p_scalar(Qrec.getPoint(), ecc.getGeneratorOrder());
                if(O.isIdentity())
                {
                    cout << hex << Qrec.getAddress() << endl;
                    return 0;
                }
            }
        }
    }*/

    /*Pubkey k;
    const char *message = "hello";
    Bitstream t_raw(message,strlen(message)<<3);
    Bitstream t_h(t_raw.keccak256());
    Privkey x(Integer(Bitstream("1", 256, 16)));
    Signature sig( Bitstream("1", 256, 16),
                   Bitstream("1", 256, 16),
                   false );
    bool bexpected = false;
    bool bactual = sig.ecrecover(k, t_h);
     return 0;*/

     /*bool found = false;
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

    Mnemonic *mnc = new Mnemonic(128);
    //Mnemonic *mnc = new Mnemonic(160);
    //Mnemonic *mnc = new Mnemonic(192);
    //Mnemonic *mnc = new Mnemonic(224);
    //Mnemonic *mnc = new Mnemonic(256);

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

    cout << hex << ecc.getGeneratorOrder() << endl;
    cout << dec << ecc.getGeneratorOrder().size_in_base(2) << endl;
    Privkey m(mnc->get_seed("LEDGER"), Privkey::Format::SEED, ecc);
    Privkey m_h44(m,44,true);
    Privkey m_h44_h60(m_h44,60,true);
    Privkey m_h44_h60_h0(m_h44_h60,0,true);
    Privkey m_h44_h60_h0_0(m_h44_h60_h0,0,false);
    int32_t _x = 3;
    Privkey m_h44_h60_h0_0_x(m_h44_h60_h0_0,_x,false);

    cout << "Address: " << hex << m_h44_h60_h0_0_x.getPubKey().getAddress() << endl << endl;;

    delete mnc;*/

    return 0;
}
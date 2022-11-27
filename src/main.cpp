#include "crypto/bips.h"

using namespace BIP39;
using namespace BIP32;

int main(int argc, char** argv)
{
    mnemonic* mnc = new mnemonic(256);

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

    seed s(*mnc, "toto");
    extprivkey m(s);
    extprivkey m_h44(m,44,true);
    extprivkey m_h44_h60(m_h44,60,true);
    extprivkey m_h44_h60_h0(m_h44_h60,0,true);
    extprivkey m_h44_h60_h0_0(m_h44_h60_h0,0,false);
    int32_t x = 3;
    extprivkey m_h44_h60_h0_0_x(m_h44_h60_h0_0,x,false);

    cout << hex << m_h44_h60_h0_0_x.getExtPubKey().getAddress() << endl;

    delete mnc;

    return 0;
}
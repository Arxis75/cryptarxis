#include <reactor/InitiationDispatcher.h>
#include <reactor/SocketHandler.h>

#include <crypto/bips.h>

#include <tools/rlp.h>

#define PORT 40404


#include <crypto/bips.h>
using namespace BIP39;
using namespace Givaro;
int main(int argc , char *argv[])  
{

    RLPByteStream rlp_data1("f905c201822db4850cf4c8f45c8304b56594d02c359ba867796c5a595c66f914dec0e37abc7b80b8a4ecfc9f5e000000000000000000000000d51a44d3fae010294c616388b506acda1bfaae460000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000003585bc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000011f8339276f904b2f902ac94d51a44d3fae010294c616388b506acda1bfaae46f90294a00000000000000000000000000000000000000000000000000000000000000011a0000000000000000000000000000000000000000000000000000000000000000ea0000000000000000000000000000000000000000000000000000000000000001aa0000000000000000000000000000000000000000000000000000000000000001ea00000000000000000000000000000000000000000000000000000000000000007a00000000000000000000000000000000000000000000000000000000000000005a00000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000aa0000000000000000000000000000000000000000000000000000000000000000ca0d833147d7dc355ba459fc788f669e58cfaf9dc25ddcd0702e87d69c7b5124289a00000000000000000000000000000000000000000000000000000000000000010a00000000000000000000000000000000000000000000000000000000000000001a0000000000000000000000000000000000000000000000000000000000000001da0d833147d7dc355ba459fc788f669e58cfaf9dc25ddcd0702e87d69c7b512428aa00000000000000000000000000000000000000000000000000000000000000017a00000000000000000000000000000000000000000000000000000000000000003a0000000000000000000000000000000000000000000000000000000000000001ca00000000000000000000000000000000000000000000000000000000000000023a0d833147d7dc355ba459fc788f669e58cfaf9dc25ddcd0702e87d69c7b512428ba00000000000000000000000000000000000000000000000000000000000000002f87a94c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2f863a0cbfe8b515cbdedd534543fab9b8cd0add753173ced79c5adc0a43c32fa2430cfa0ad97560a268614f479889591062e8a5bcb0ab0e01761e16df370e46f8fd2b2eda09b354f30d74ca151470e4c01c97d425c838beac0ab30a0bd396660e4405f8beed6948f68f4810cce3194b6cb6f3d50fa58c2c9bdd1d5c0f8fe94dac17f958d2ee523a2206206994597c13d831ec7f8e7a00000000000000000000000000000000000000000000000000000000000000000a032386aa1ea2888e40243b524a67e7408609a4257cebaa46f72ca08964fad63c9a0000000000000000000000000000000000000000000000000000000000000000aa00000000000000000000000000000000000000000000000000000000000000003a00000000000000000000000000000000000000000000000000000000000000004a0eb449bc003e7395128833de1fb3384246962a9d4d29c66083486accd9139c704a09c6eac2ef8805f7aa2534fea9ff36aaf0fa5c6bc4f929642813bb168ea8c5e6af794c4ad29ba4b3c580e6d59105fff484999997675ffe1a00000000000000000000000000000000000000000000000000000000000000004f794d02c359ba867796c5a595c66f914dec0e37abc7be1a0c85b1f5559310c833a70b1e26c742ff5e20cd6d984e1ae9c4d82f7d7c31394c401a01a2ea66c572e7a26f59fd562b5acf2e08c87ec90ffc92bff2ab928f688c96aa1a04e897a5aae9a1a46fbc7f599fe60c497237a2ae3c27007abc44a239673def866", false, false);
    vector<RLPByteStream> v1 = rlp_data1.decodeList();
    ByteStream chain_id(v1[0].decode());
    ByteStream nonce(v1[1].decode());
    ByteStream gas_price(v1[2].decode());
    ByteStream gas_limit(v1[3].decode());
    ByteStream to(v1[4].decode());
    ByteStream value(v1[5].decode());
    ByteStream data(v1[6].decode());
    RLPByteStream access_list(v1[7]);
    vector<RLPByteStream> v2 = access_list.decodeList();
    vector<RLPByteStream> v3 = v2[0].decodeList();
    ByteStream access_list_addr0(v3[0].decode());
    vector<RLPByteStream> v4 = v3[1].decodeList();
    ByteStream access_list_code9(v4[9].decode());
    ByteStream signature_y_parity(v1[8].decode());
    ByteStream signature_r(v1[9].decode());
    ByteStream signature_s(v1[10].decode());
    /*
    0x02
    f873
    01
    01
    8458370200
    8506bcfcef3a
    825208
    9429eca176157ba854c2dd7a14a27b4a253c8a01c9
    884639df38ec69f3bc
    80
    c0
    01
    a0da23340cb8a3e75917bfc2a3cb3685046ee3bdb8527bb0b3f455baafba235ce4
    a01d2bb7a39793211811face204c35fa9de11229b93f3a300f0c512ec8ffd11a31
    
    RLP list/size:              0xf7+0x01/  0x09(headers)+0x6A (payload)  > 55 bytes
    +chain_id                               0x01                    (EIP2930)
    nonce                                   0x01
    +max_priority_fee_per_gas   0x80+0x04/  0x58370200              (EIP1559)
    +max_fee_per_gas            80+0x05/    0x06bcfcef3a            (EIP1559)
    gas_limit                   0x80+0x02/  0x5208
    to                          0x80+0x14/  29eca176157ba854c2dd7a14a27b4a253c8a01c9
    eth                         0x80+0x08/  0x4639df38ec69f3bc
    data                        0x80/
    +access_list                0xc0/                               (EIP2930)
    +signature_y_parity                     0x01                    (EIP2930)
    signature_r                 0x80+0x20/  0xda23340cb8a3e75917bfc2a3cb3685046ee3bdb8527bb0b3f455baafba235ce4
    signature_s                 0x80+0x20/  0x1d2bb7a39793211811face204c35fa9de11229b93f3a300f0c512ec8ffd11a31
    */

    Privkey node_secret(ByteStream("0xb71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291", 32, 16));
    
    //vector<RLPByteStream> payload;
    RLPByteStream payload;
    payload.push_back(RLPByteStream(1, 4));

    payload.push_back(RLPByteStream("id"));
    payload.push_back(RLPByteStream("v4"));

    payload.push_back(RLPByteStream("ip"));
    payload.push_back(RLPByteStream(0x7f000001, 4));     // 127.0.0.1
    //ByteStream ip_value(0x51430B52, 4);   // 81.67.11.82

    payload.push_back(RLPByteStream("secp256k1"));
    payload.push_back(RLPByteStream(node_secret.getPubKey().getKey(Pubkey::Format::PREFIXED_X)));
    
    //RLPByteStream tcp_key("tcp");
    //RLPByteStream tcp_value(30303, 2);
    
    payload.push_back(RLPByteStream("udp"));
    payload.push_back(RLPByteStream(30303, 2));

    RLPByteStream enr_content(payload);

    Signature sig = node_secret.sign(enr_content.keccak256());
    ByteStream r(sig.get_r(), 32);
    ByteStream s(sig.get_s(), 32);
    ByteStream enr_signature;
    enr_signature.push_back(r);
    enr_signature.push_back(s);
    cout << hex << enr_signature << endl;

    ByteStream node_id(node_secret.getPubKey().getKey(Pubkey::Format::XY).keccak256());
    cout << hex << node_id << endl;

    ByteStream enr_record;
    enr_record.push_back(enr_signature);
    enr_record.push_back(enr_content);

    // Initialize logging server endpoint and
    // register with the Initiation_Dispatcher.
    SocketHandler tcp_server(PORT, IPPROTO_TCP);
    SocketHandler udp_server(PORT, IPPROTO_UDP);

    // Main event loop that handles client
    // logging records and connection requests.
    while(true)
        Initiation_Dispatcher::GetInstance().handle_events();
         
    return 0;  
}  
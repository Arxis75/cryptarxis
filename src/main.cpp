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

    vector<RLPByteStream> v;
    v.push_back(RLPByteStream(0x01,1));    
    v.push_back(RLPByteStream(0x01, 1));
    v.push_back(RLPByteStream(0x58370200, 4));
    v.push_back(RLPByteStream(0x06bcfcef3a, 5));
    v.push_back(RLPByteStream(0x5208, 2));
    v.push_back(RLPByteStream("0x29eca176157ba854c2dd7a14a27b4a253c8a01c9", 20, 16));
    v.push_back(RLPByteStream(0x4639df38ec69f3bc, 8));
    v.push_back(RLPByteStream());
    v.push_back(RLPByteStream(true));
    v.push_back(RLPByteStream(0x01, 1));
    v.push_back(RLPByteStream("0xda23340cb8a3e75917bfc2a3cb3685046ee3bdb8527bb0b3f455baafba235ce4", 32, 16));
    v.push_back(RLPByteStream("0x1d2bb7a39793211811face204c35fa9de11229b93f3a300f0c512ec8ffd11a31", 32, 16));
    RLPByteStream payload(v);
    cout << payload << endl;

    Privkey node_secret(ByteStream("0xb71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291", 16));
    
    ByteStream seq(1, 4);

    ByteStream id_key("id",2);
    ByteStream id_value("v4",2);

    ByteStream ip_key("ip",2);
    ByteStream ip_value(0x7f000001, 4);     // 127.0.0.1
    //ByteStream ip_value(0x51430B52, 4);   // 81.67.11.82

    ByteStream secp256k1_key("secp256k1", 9);
    ByteStream secp256k1_value = node_secret.getPubKey().getKey(Pubkey::Format::PREFIXED_X);
    
    ByteStream tcp_key("tcp",3);
    ByteStream tcp_value(30303, 2);
    
    ByteStream udp_key("udp",3);
    ByteStream udp_value(30303, 2);

    ByteStream enr_content;
    enr_content.push_back(ByteStream(0xf846, 2));

    enr_content.push_back(ByteStream(0x88, 4));
    enr_content.push_back(seq);

    enr_content.push_back(ByteStream(0x82, 2));
    enr_content.push_back(id_key);
    enr_content.push_back(ByteStream(0x82, 2));
    enr_content.push_back(id_value);
    
    enr_content.push_back(ByteStream(0x89, 9));
    enr_content.push_back(secp256k1_key);
    enr_content.push_back(ByteStream(0xA1, 33));
    enr_content.push_back(secp256k1_value);

    enr_content.push_back(ByteStream(0x82, 2));
    enr_content.push_back(ip_key);
    enr_content.push_back(ByteStream(0x84, 4));
    enr_content.push_back(ip_value);

    enr_content.push_back(ByteStream(0x83, 3));
    enr_content.push_back(udp_key);
    enr_content.push_back(ByteStream(0x82, 2));
    enr_content.push_back(udp_value);

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
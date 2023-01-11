#include <reactor/InitiationDispatcher.h>
#include <reactor/SocketHandler.h>

#include <crypto/bips.h>

#include <tools/rlp.h>

#define PORT 40404
     
int main(int argc , char *argv[])  
{   
    Privkey node_secret(Bitstream("0xb71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291", 256, 16));
    
    Bitstream seq(1, 64);

    Bitstream id_key("id",16);
    Bitstream id_value("v4",16);

    Bitstream ip_key("ip",16);
    Bitstream ip_value(0x7f000001, 32);     // 127.0.0.1
    //Bitstream ip_value(0x51430B52, 32);   // 81.67.11.82

    Bitstream secp256k1_key("secp256k1", 72);
    Bitstream secp256k1_value = node_secret.getPubKey().getKey(Pubkey::Format::PREFIXED_X);
    
    Bitstream tcp_key("tcp",24);
    Bitstream tcp_value(30303, 16);
    
    Bitstream udp_key("udp",24);
    Bitstream udp_value(30303, 16);

    Bitstream enr_content;
    enr_content.push_back(Bitstream(0xf846, 16), 16);

    enr_content.push_back(Bitstream(0x88, 64), 64);
    enr_content.push_back(seq, seq.bitsize());

    /*enr_content.push_back(Bitstream(0x82, 16), 16);
    enr_content.push_back(id_key, id_key.bitsize());
    enr_content.push_back(Bitstream(0x82, 16), 16);
    enr_content.push_back(id_value, id_value.bitsize());
    
    enr_content.push_back(Bitstream(0x89, 72), 72);
    enr_content.push_back(secp256k1_key, secp256k1_key.bitsize());
    enr_content.push_back(Bitstream(0xA1, 264), 264);
    enr_content.push_back(secp256k1_value, secp256k1_value.bitsize());

    enr_content.push_back(Bitstream(0x82, 16), 16);
    enr_content.push_back(ip_key, ip_key.bitsize());
    enr_content.push_back(Bitstream(0x84, 32), 32);
    enr_content.push_back(ip_value, ip_value.bitsize());

    enr_content.push_back(Bitstream(0x83, 24), 24);
    enr_content.push_back(udp_key, udp_key.bitsize());
    enr_content.push_back(Bitstream(0x82, 16), 16);
    enr_content.push_back(udp_value, udp_value.bitsize());*/

    enr_content.push_back(Bitstream(0x84, 32), 32);
    enr_content.push_back(id_key, id_key.bitsize());
    enr_content.push_back(id_value, id_value.bitsize());

    enr_content.push_back(Bitstream(0xAA, 336), 336);
    enr_content.push_back(secp256k1_key, secp256k1_key.bitsize());
    enr_content.push_back(secp256k1_value, secp256k1_value.bitsize());
    
    enr_content.push_back(Bitstream(0x86, 48), 48);
    enr_content.push_back(ip_key, ip_key.bitsize());
    enr_content.push_back(ip_value, ip_value.bitsize());

    enr_content.push_back(Bitstream(0x85, 40), 40);
    enr_content.push_back(udp_key, udp_key.bitsize());
    enr_content.push_back(udp_value, udp_value.bitsize());

    Signature sig = node_secret.sign(enr_content.keccak256());
    Bitstream r(sig.get_r(), 256);
    Bitstream s(sig.get_s(), 256);
    Bitstream enr_signature;
    enr_signature.push_back(r, r.bitsize());
    enr_signature.push_back(s, s.bitsize());
    cout << hex << enr_signature << endl;

    Bitstream node_id(node_secret.getPubKey().getKey(Pubkey::Format::XY).keccak256());
    cout << hex << node_id << endl;

    Bitstream enr_record;
    enr_record.push_back(enr_signature, enr_signature.bitsize());
    enr_record.push_back(enr_content, enr_content.bitsize());

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
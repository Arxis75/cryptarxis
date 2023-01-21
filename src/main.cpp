#include <reactor/InitiationDispatcher.h>
#include <reactor/SocketHandler.h>

#include <crypto/bips.h>
#include <tools/rlp.h>

#define PORT 40404

int main(int argc , char *argv[])  
{
    //+chain_id                               0x01                    (EIP2930)
    //nonce                                   0x01
    //+max_priority_fee_per_gas   0x80+0x04/  0x58370200              (EIP1559)
    //+max_fee_per_gas            80+0x05/    0x06bcfcef3a            (EIP1559)
    //gas_limit                   0x80+0x02/  0x5208
    //to                          0x80+0x14/  29eca176157ba854c2dd7a14a27b4a253c8a01c9
    //eth                         0x80+0x08/  0x4639df38ec69f3bc
    //data                        0x80/
    //+access_list                0xc0/                               (EIP2930)
    //+signature_y_parity                     0x01                    (EIP2930)
    //signature_r                 0x80+0x20/  0xda23340cb8a3e75917bfc2a3cb3685046ee3bdb8527bb0b3f455baafba235ce4
    //signature_s                 0x80+0x20/  0x1d2bb7a39793211811face204c35fa9de11229b93f3a300f0c512ec8ffd11a31

    RLPByteStream rlp_data1( "f873010184583702008506bcfcef3a8252089429eca176157ba854c2dd7a14a2"
                             "7b4a253c8a01c9884639df38ec69f3bc80c001a0da23340cb8a3e75917bfc2a3"
                             "cb3685046ee3bdb8527bb0b3f455baafba235ce4a01d2bb7a39793211811face"
                             "204c35fa9de11229b93f3a300f0c512ec8ffd11a31" );

    RLPByteStream rlp_data2; 
    rlp_data2.push_back(ByteStream(0x01));
    rlp_data2.push_back(ByteStream(0x01));
    rlp_data2.push_back(ByteStream(0x58370200));
    rlp_data2.push_back(ByteStream(0x06bcfcef3a));
    rlp_data2.push_back(ByteStream(0x5208));
    rlp_data2.push_back(ByteStream("0x29eca176157ba854c2dd7a14a27b4a253c8a01c9", 20, 16));
    rlp_data2.push_back(ByteStream(0x4639df38ec69f3bc));
    rlp_data2.push_back(ByteStream());
    rlp_data2.push_back(RLPByteStream(ByteStream(), true));
    rlp_data2.push_back(ByteStream(0x01));
    rlp_data2.push_back(ByteStream("0xda23340cb8a3e75917bfc2a3cb3685046ee3bdb8527bb0b3f455baafba235ce4", 32, 16));
    rlp_data2.push_back(ByteStream("0x1d2bb7a39793211811face204c35fa9de11229b93f3a300f0c512ec8ffd11a31", 32, 16));

    if( rlp_data1 == rlp_data2 )
        cout << "Yay! RLP encoding good!" << endl;
    else
    {
        cout << hex << rlp_data1 << endl;
        cout << hex << rlp_data2 << endl;
    }

    RLPByteStream rlp_data3( "f9055401826eb780850e78a5df3383124f8094a57bd00134b2850b2a1c55860c"
                             "9e9ea100fdd6cf80b902041cff79cd000000000000000000000000aa2ec16d77"
                             "cfc057fb9c516282fef9da9de1e9870000000000000000000000000000000000"
                             "0000000000000000000000000000400000000000000000000000000000000000"
                             "0000000000000000000000000001844f0c7c0a00000000000000000000000000"
                             "00000000000000000000000000000000000bb8000000000000000000000000c0"
                             "2aaa39b223fe8d0a0e5c4f27ead9083c756cc2000000000000000000000000da"
                             "c17f958d2ee523a2206206994597c13d831ec700000000000000000000000056"
                             "178a0d5f301baf6cf3e1cd53d9863437345bf900000000000000000000000000"
                             "0000000000000000000000002386f26fc1000000000000000000000000000000"
                             "00000000000000000000a2a15d09519be0000000000000000000000000000000"
                             "0000000000000000cd5d9c9ffa83c88707540000000000000000000000000000"
                             "00000000000000000000002ad622051f0a400000000000000000000000000000"
                             "000000000000000003a5828e00e9d7bb9b347e00000000000000000000000000"
                             "00000000000000000000000de0b6b3a764000000000000000000000000000000"
                             "000000000000000000000000000000612782c200000000000000000000000000"
                             "0000000000000000000000000000000000003300000000000000000000000000"
                             "000000000000000000000000000000f902e2d694a56006a9bc78fd64404b34d4"
                             "4f06d1141f8589bec0d694e592427a0aece92de3edee1f18e0157c05861564c0"
                             "f8fe94dac17f958d2ee523a2206206994597c13d831ec7f8e7a0f79325ef15d7"
                             "3bc873d975b0e4eedaf108f1a270300e4b40424347eae19bc685a0af50917ef2"
                             "66a63852df327a118d37bd04d770347c3dfc528d177928d9263066a000000000"
                             "00000000000000000000000000000000000000000000000000000000a0000000"
                             "000000000000000000000000000000000000000000000000000000000aa00000"
                             "000000000000000000000000000000000000000000000000000000000004a000"
                             "00000000000000000000000000000000000000000000000000000000000003a0"
                             "447ca931bbc745ec7d2310d11914e4e40b840765b32592a566191228fbbd2ce4"
                             "d694aa2ec16d77cfc057fb9c516282fef9da9de1e987c0f8bc94c02aaa39b223"
                             "fe8d0a0e5c4f27ead9083c756cc2f8a5a00a57c8bae4ecff7c613785bbda00a6"
                             "9fbdda07ce911b9bfb285742752e6b4215a030bd84b96629f958113934633d3b"
                             "d1b64c3d259a85c57ceac65da8c5ec9bf3a7a0b0b00dbdb054c95b5c2e5f3f7f"
                             "acd24c4530e27329e985fe8efb5f6876c253f9a0217fdff7afc5cd5a4e8ef414"
                             "6b5a8c30926ffa20f0ff879ffdc9ed3476cd86eea040f963d8ab5de5259e130f"
                             "6865b75ceb44638428ca149b7fe63a511f142fedb7f8dd944e68ccd3e89f51c3"
                             "074ca5072bbac773960dfa36f8c6a0ad860a26b2adedd5a0c5d198c9503a420b"
                             "a615f9041c00093858eff051edf0a0a000000000000000000000000000000000"
                             "00000000000000000000000000000001a0000000000000000000000000000000"
                             "0000000000000000000000000000000000a00000000000000000000000000000"
                             "000000000000000000000000000000000004a000000000000000000000000000"
                             "0000000000000000000000000000000000000da0000000000000000000000000"
                             "000000000000000000000000000000000000000c01a0cba87bd34ba8ff68e25d"
                             "6b7ebd29833d64f52f2b9c2b835183b830c9dec091eba0307598bd8cb3b2c8f1"
                             "ae26f5faab724bd682a898983f9116d989e05b71836c36" );
    
    ByteStream chain_id = rlp_data3.pop_front();
    ByteStream nonce = rlp_data3.pop_front();
    ByteStream max_priority_fee_per_gas = rlp_data3.pop_front();
    ByteStream max_fee_per_gas = rlp_data3.pop_front();
    ByteStream gas_limit = rlp_data3.pop_front();
    ByteStream to = rlp_data3.pop_front();
    ByteStream eth = rlp_data3.pop_front();
    ByteStream data = rlp_data3.pop_front();
    RLPByteStream access_list = rlp_data3.pop_front();
    ByteStream signature_y_parity = rlp_data3.pop_front();
    ByteStream signature_r = rlp_data3.pop_front();
    ByteStream signature_s = rlp_data3.pop_front();
    
    //-----------------------------------------

    Privkey node_secret(ByteStream("0xb71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291", 32, 16));

    RLPByteStream rlp;
    rlp.push_back(RLPByteStream(ByteStream(1, 1)));

    rlp.push_back(RLPByteStream(ByteStream("id")));
    rlp.push_back(RLPByteStream(ByteStream("v4")));

    rlp.push_back(RLPByteStream(ByteStream("ip")));
    rlp.push_back(RLPByteStream(ByteStream(0x7f000001, 4)));     // 127.0.0.1
    //ByteStream ip_value(0x51430B52, 4);   // 81.67.11.82

    rlp.push_back(RLPByteStream(ByteStream("secp256k1")));
    rlp.push_back(RLPByteStream(ByteStream(node_secret.getPubKey().getKey(Pubkey::Format::PREFIXED_X))));
    
    //rlp.push_back(RLPByteStream(ByteStream("tcp")));
    //rlp.push_back(RLPByteStream(ByteStream(30303, 2)));
    
    rlp.push_back(RLPByteStream(ByteStream("udp")));
    rlp.push_back(RLPByteStream(ByteStream(30303, 2)));

    Signature sig = node_secret.sign(rlp.keccak256());
    ByteStream enr_signature;
    enr_signature.push_back(ByteStream(sig.get_r(), 32));
    enr_signature.push_back(ByteStream(sig.get_s(), 32));
    cout << hex << enr_signature << endl;

    rlp.push_front(RLPByteStream(enr_signature));
    cout << hex << rlp << endl;
    
    string expected("-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8");
    string actual = base64_url_encode(rlp);

    if( !strcmp(expected.c_str(), actual.c_str()) )
    {
        cout << hex << "enr:" << actual << endl;
        cout << "Yay! ENR base64 encoding good!" << endl;
    }
    else
    {
        cout << hex << "enr:" << expected << endl;
        cout << hex << "enr:" << actual << endl;
    }

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
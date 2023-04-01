#include <p2p/Network.h>
#include "Common.h"
#include <crypto/bips.h>
#include <crypto/AES.h>

#include <p2p/DiscV5.h>
#include <p2p/DiscV5Msg.h>
#include "Common.h"

//#define NODE_IP 0x51430B52       //81.67.11.82
#define NODE_IP 0x5B5A2C19       //91.90.44.25
#define NODE_UDP_PORT 56051      //40404
#define NODE_TCP_PORT 56051      //40404
#define NODE_SECRET "0x4bbede0846299a5893929f9ebbadcd93933b91c8f4d1f7fe8d7f485c9b168817"    //some random privkey

#include <p2p/DiscV4.h>
#define CLIENT_IP 0x51430B52      //81.67.11.82
#define CLIENT_UDP_PORT 50505
#define CLIENT_TCP_PORT 50505
#define CLIENT_SECRET "0x3bbede0846299a5893929f9ebbadcd93933b91c8f4d1f7fe8d7f485c9b168815"    //some random privkey

// ENR TEST VECTOR
//#define NODE_TCP_PORT 30303
//#define NODE_UDP_PORT 30303
//#define NODE_IP 0x7F000001      //127.0.0.1
//#define NODE_SECRET "0xb71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291"

int main(void)
{
    //Network::GetInstance().start(NODE_IP, 40404, 40404, NODE_SECRET, "discv4");
    Network::GetInstance().start(NODE_IP, 8000, 8000, NODE_SECRET, "discv5");

    if( auto server = const_pointer_cast<DiscV5Server>(dynamic_pointer_cast<const DiscV5Server>(Network::GetInstance().getUDPServer())) )
    {
        string bootstrap_nodes[11];
        // Teku team's bootnode
        bootstrap_nodes[0] = "enr:-KG4QOtcP9X1FbIMOe17QNMKqDxCpm14jcX5tiOE4_TyMrFqbmhPZHK_ZPG2Gxb1GE2xdtodOfx9-cgvNtxnRyHEmC0ghGV0aDKQ9aX9QgAAAAD__________4JpZIJ2NIJpcIQDE8KdiXNlY3AyNTZrMaEDhpehBDbZjM_L9ek699Y7vhUJ-eAdMyQW_Fil522Y0fODdGNwgiMog3VkcIIjKA";
        bootstrap_nodes[1] = "enr:-KG4QDyytgmE4f7AnvW-ZaUOIi9i79qX4JwjRAiXBZCU65wOfBu-3Nb5I7b_Rmg3KCOcZM_C3y5pg7EBU5XGrcLTduQEhGV0aDKQ9aX9QgAAAAD__________4JpZIJ2NIJpcIQ2_DUbiXNlY3AyNTZrMaEDKnz_-ps3UUOfHWVYaskI5kWYO_vtYMGYCQRAR3gHDouDdGNwgiMog3VkcIIjKA";
        // Prylab team's bootnodes
        bootstrap_nodes[2] = "enr:-Ku4QImhMc1z8yCiNJ1TyUxdcfNucje3BGwEHzodEZUan8PherEo4sF7pPHPSIB1NNuSg5fZy7qFsjmUKs2ea1Whi0EBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpD1pf1CAAAAAP__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQOVphkDqal4QzPMksc5wnpuC3gvSC8AfbFOnZY_On34wIN1ZHCCIyg";
        bootstrap_nodes[3] = "enr:-Ku4QP2xDnEtUXIjzJ_DhlCRN9SN99RYQPJL92TMlSv7U5C1YnYLjwOQHgZIUXw6c-BvRg2Yc2QsZxxoS_pPRVe0yK8Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpD1pf1CAAAAAP__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQMeFF5GrS7UZpAH2Ly84aLK-TyvH-dRo0JM1i8yygH50YN1ZHCCJxA";
        bootstrap_nodes[4] = "enr:-Ku4QPp9z1W4tAO8Ber_NQierYaOStqhDqQdOPY3bB3jDgkjcbk6YrEnVYIiCBbTxuar3CzS528d2iE7TdJsrL-dEKoBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpD1pf1CAAAAAP__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQMw5fqqkw2hHC4F5HZZDPsNmPdB1Gi8JPQK7pRc9XHh-oN1ZHCCKvg";
        // Lighthouse team's bootnodes
        bootstrap_nodes[5] = "enr:-IS4QLkKqDMy_ExrpOEWa59NiClemOnor-krjp4qoeZwIw2QduPC-q7Kz4u1IOWf3DDbdxqQIgC4fejavBOuUPy-HE4BgmlkgnY0gmlwhCLzAHqJc2VjcDI1NmsxoQLQSJfEAHZApkm5edTCZ_4qps_1k_ub2CxHFxi-gr2JMIN1ZHCCIyg";
        bootstrap_nodes[6] = "enr:-IS4QDAyibHCzYZmIYZCjXwU9BqpotWmv2BsFlIq1V31BwDDMJPFEbox1ijT5c2Ou3kvieOKejxuaCqIcjxBjJ_3j_cBgmlkgnY0gmlwhAMaHiCJc2VjcDI1NmsxoQJIdpj_foZ02MXz4It8xKD7yUHTBx7lVFn3oeRP21KRV4N1ZHCCIyg";
        // EF bootnodes
        bootstrap_nodes[7] = "enr:-Ku4QHqVeJ8PPICcWk1vSn_XcSkjOkNiTg6Fmii5j6vUQgvzMc9L1goFnLKgXqBJspJjIsB91LTOleFmyWWrFVATGngBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhAMRHkWJc2VjcDI1NmsxoQKLVXFOhp2uX6jeT0DvvDpPcU8FWMjQdR4wMuORMhpX24N1ZHCCIyg";
        bootstrap_nodes[8] = "enr:-Ku4QG-2_Md3sZIAUebGYT6g0SMskIml77l6yR-M_JXc-UdNHCmHQeOiMLbylPejyJsdAPsTHJyjJB2sYGDLe0dn8uYBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhBLY-NyJc2VjcDI1NmsxoQORcM6e19T1T9gi7jxEZjk_sjVLGFscUNqAY9obgZaxbIN1ZHCCIyg";
        bootstrap_nodes[9] = "enr:-Ku4QPn5eVhcoF1opaFEvg1b6JNFD2rqVkHQ8HApOKK61OIcIXD127bKWgAtbwI7pnxx6cDyk_nI88TrZKQaGMZj0q0Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhDayLMaJc2VjcDI1NmsxoQK2sBOLGcUb4AwuYzFuAVCaNHA-dy24UuEKkeFNgCVCsIN1ZHCCIyg";
        bootstrap_nodes[10] = "enr:-Ku4QEWzdnVtXc2Q0ZVigfCGggOVB2Vc1ZCPEc6j21NIFLODSJbvNaef1g4PxhPwl_3kax86YPheFUSLXPRs98vvYsoBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhDZBrP2Jc2VjcDI1NmsxoQM6jr8Rb1ktLEsVcKAPa08wCsKUmvoQ8khiOl_SLozf9IN1ZHCCIyg";
        //local discv5-cli
        string cli = "enr:-IS4QJ9ci200iFfE3fQbIal2SzJI6ZjdteqDENZSAqOLRrlGGdWQGhFkDbUG719gsaxIwZy8IOmj3tyS7WgF8j7h_bgBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQKWJxnv3cjOpy4moB1PEAtXhFpmoq8oYPwhFb8icUHvlIN1ZHCCIyg";
        //string cli = "enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8";
        
        for(int i=0;i<=10;i++)
        {
            string enr_record = bootstrap_nodes[i];
            string bootstrap_node_str = base64_url_decode(enr_record.substr(4, enr_record.size() - 4));
            RLPByteStream bootstrap_node((uint8_t*)bootstrap_node_str.c_str(), bootstrap_node_str.size());
            
            auto bootstrap_node_id = make_shared<const ENRV4Identity>(bootstrap_node);

            if( auto session = dynamic_pointer_cast<const DiscV5Session>(server->registerSessionHandler(bootstrap_node_id->getUDPAddress())) )
            {
                const_pointer_cast<DiscV5Session>(session)->updatePeerENR(bootstrap_node_id);
                const_pointer_cast<DiscV5Session>(session)->sendPing();
            }
        }

        while(true)
            Initiation_Dispatcher::GetInstance().handle_events();
    }

    /*auto host_enr = make_shared<const ENRV4Identity>(1, NODE_IP, NODE_UDP_PORT, NODE_TCP_PORT, NODE_SECRET);
    auto udp_server = make_shared<DiscV4Server>(host_enr);
    udp_server->start();

    auto client_enr = make_shared<const ENRV4Identity>(1, CLIENT_IP, CLIENT_UDP_PORT, CLIENT_TCP_PORT, CLIENT_SECRET);
    auto udp_client = make_shared<DiscV4Server>(client_enr);
    udp_client->start();

    std::cout << "Server ID = " << host_enr->getID() << std::endl;
    std::cout << "Client ID = " << client_enr->getID() << std::endl;

    udp_client->onNewNodeCandidates({{host_enr}});

    while(true)
        Initiation_Dispatcher::GetInstance().handle_events();*/


    /*ByteStream challenge_data;
    DiscV5AuthMessage m( shared_ptr<const SessionHandler>(nullptr),
                           ByteStream("0xbbbb9d047f0488c0b5a93c1c3f2d8bafc7c8ff337024a55434a0d0555de64db9", 32, 16),
                           ByteStream("0x0102030405060708090a0b0c", 12, 16),
                           challenge_data,
                           0);

    ByteStream ping("00000000000000000000000000000000088b3d4342774649325f313964a39e55ea96c005ad52be8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d34c4f53245d08dab84102ed931f66d1492acb308fa1c6715b9d139b81acbdcc", 95, 16);
    ByteStream ping_session_key("0x00000000000000000000000000000000", 16, 16);
    ByteStream who_are_you("00000000000000000000000000000000088b3d434277464933a1ccc59f5967ad1d6035f15e528627dde75cd68292f9e6c27d6b66c8100a873fcbaed4e16b8d", 63, 16);
    ByteStream ping_handshake("00000000000000000000000000000000088b3d4342774649305f313964a39e55ea96c005ad521d8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d34c4f53245d08da4bb252012b2cba3f4f374a90a75cff91f142fa9be3e0a5f3ef268ccb9065aeecfd67a999e7fdc137e062b2ec4a0eb92947f0d9a74bfbf44dfba776b21301f8b65efd5796706adff216ab862a9186875f9494150c4ae06fa4d1f0396c93f215fa4ef524f1eadf5f0f4126b79336671cbcf7a885b1f8bd2a5d839cf8", 194, 16);
    ByteStream ping_handshake_session_key("0x4f9fac6de7567d1e3b1241dffe90f662", 16, 16);
    ByteStream ping_handshake_with_enr("00000000000000000000000000000000088b3d4342774649305f313964a39e55ea96c005ad539c8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d34c4f53245d08da4bb23698868350aaad22e3ab8dd034f548a1c43cd246be98562fafa0a1fa86d8e7a3b95ae78cc2b988ded6a5b59eb83ad58097252188b902b21481e30e5e285f19735796706adff216ab862a9186875f9494150c4ae06fa4d1f0396c93f215fa4ef524e0ed04c3c21e39b1868e1ca8105e585ec17315e755e6cfc4dd6cb7fd8e1a1f55e49b4b5eb024221482105346f3c82b15fdaae36a3bb12a494683b4a3c7f2ae41306252fed84785e2bbff3b022812d0882f06978df84a80d443972213342d04b9048fc3b1d5fcb1df0f822152eced6da4d3f6df27e70e4539717307a0208cd208d65093ccab5aa596a34d7511401987662d8cf62b139471", 321, 16);
    ByteStream ping_handshake_with_enr_session_key("0x53b1c075f41876423154e157470c2f48", 16, 16);

    ByteStream packet = ping_handshake_with_enr;
    ByteStream session_key = ping_handshake_with_enr_session_key;

    ByteStream masking_iv(&packet[0], 16);
    ByteStream masked_header(&packet[16], packet.byteSize() - 16);
    ByteStream header(Integer::zero, masked_header.byteSize());

    ByteStream dest_node_id("0xbbbb9d047f0488c0b5a93c1c3f2d8bafc7c8ff337024a55434a0d0555de64db9", 32, 16);
    ByteStream masking_key(&dest_node_id[0], 16);

    ctr_decrypt(masked_header, masked_header.byteSize(),
                masking_key,
                masking_iv, masking_iv.byteSize(),
                header);

    //-------------------------------------------------------------------
    // header = ByteStream("646973637635000100ffffffffffffffffffffffff0020aaaa8419e9f49d0083561b48287df592939a8d19947d8c0ef88f2a4856a69fbb", 55, 16);

    ByteStream protocol_id(&header[0], 6);
    ByteStream version(&header[6], 2);
    ByteStream flag(&header[8], 1);
    ByteStream nonce(&header[9], 12);
    ByteStream authdata_size(&header[21], 2);
    ByteStream authdata(&header[23], authdata_size.as_uint64());

    assert(flag.as_uint8() < 3);

    if (flag.as_uint8() == 0)
        ByteStream src_id(&authdata[0], 32);
    if (flag.as_uint8() == 1)
    {
        ByteStream id_nonce(&authdata[0], 16);
        ByteStream enr_seq(&authdata[16], 8);
    }
    else if (flag.as_uint8() == 2)
    {
        ByteStream src_id(&authdata[0], 32);
        ByteStream sig_size(&authdata[32], 1);
        ByteStream eph_key_size(&authdata[33], 1);
        // id_signature = r || s
        ByteStream id_signature(&authdata[34], sig_size.as_uint8());
        // eph_pubkey = x || y
        ByteStream eph_pubkey(&authdata[98], eph_key_size.as_uint8());
        if (authdata.byteSize() > 131)
        {
            ByteStream enr(&authdata[131], authdata.byteSize() - 131);
            std::cout << std::hex << enr.as_Integer() << std::endl;
        }
    }

    if (flag.as_uint8() == 0 || flag.as_uint8() == 2)
    {
        // Resize the header according to the header description,
        // i.e. remove message data.
        header = header.pop_front(23 + authdata.byteSize());

        ByteStream aad;
        aad.push_back(masking_iv);
        aad.push_back(header);

        ByteStream ciphertext(&masked_header[header.byteSize()], masked_header.byteSize() - header.byteSize() - 16);
        ByteStream tag(&masked_header[masked_header.byteSize() - 16], 16);

        //-------------------------------------------------------------------

        ByteStream pt(Integer::zero, ciphertext.byteSize());

        gcm_decrypt(ciphertext, ciphertext.byteSize(),
                    aad, aad.byteSize(),
                    tag,
                    session_key,
                    nonce, nonce.byteSize(),
                    pt);

        ciphertext = ByteStream("0x00", ciphertext.byteSize(), 16);
        tag = ByteStream("0x00", 16, 16);

        gcm_encrypt(pt, pt.byteSize(),
                    aad, aad.byteSize(),
                    session_key, nonce, nonce.byteSize(),
                    ciphertext, tag);
    }*/

    return 0;
}
#include <p2p/Network.h>
#include "Common.h"
#include <crypto/bips.h>
#include <crypto/AES.h>

#include <p2p/Network.h>
#include "Common.h"

#define NODE_IP 0x51430B52      //81.67.11.82
#define NODE_UDP_PORT 40404
#define NODE_TCP_PORT 40404
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
    Network::GetInstance().start(NODE_IP, NODE_UDP_PORT, NODE_TCP_PORT, NODE_SECRET);

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
    DiscV5MaskedMessage m( shared_ptr<const SessionHandler>(nullptr),
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
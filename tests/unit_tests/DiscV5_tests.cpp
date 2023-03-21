#include <gtest/gtest.h>
#include <crypto/bips.h>
#include <p2p/DiscV5.h>
#include <p2p/DiscV5Msg.h>
#include <p2p/Network.h>

#define NODE_A_IP 0x7F000001
#define NODE_A_UDP_PORT 12345
#define NODE_A_TCP_PORT 12345
#define NODE_A_SECRET "0xeef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f"

#define NODE_B_IP 0x7F000001
#define NODE_B_UDP_PORT 54321
#define NODE_B_TCP_PORT 54321
#define NODE_B_SECRET "0x66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb1cde628"

TEST(DiscV5_tests, DiscV5_ingress_ordinary_ping)
{
    //https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire-test-vectors.md

    auto node_a_enr = make_shared<const ENRV4Identity>(0, NODE_A_IP, NODE_A_UDP_PORT, NODE_A_TCP_PORT, NODE_A_SECRET);
    auto udp_server_a = make_shared<DiscV5Server>(node_a_enr);
    
    auto node_b_enr = make_shared<const ENRV4Identity>(0, NODE_B_IP, NODE_B_UDP_PORT, NODE_B_TCP_PORT, NODE_B_SECRET);
    auto udp_server_b = make_shared<DiscV5Server>(node_b_enr);

    //Msg received by b
    auto b_session = make_shared<DiscV5Session>(udp_server_b, node_a_enr->getUDPAddress(), node_a_enr->getID());
    b_session->updatePeerENR(node_a_enr);
    b_session->setPeerSessionKey(ByteStream("0x00000000000000000000000000000000", 16, 16));
    auto a_ping_b_unauth_msg = make_shared<DiscV5UnauthMessage>( udp_server_b,
                                                                 ByteStream("0x00000000000000000000000000000000088b3d4342774649325f313964a39e55ea96c005ad52be8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d34c4f53245d08dab84102ed931f66d1492acb308fa1c6715b9d139b81acbdcc", 95, 16),
                                                                 node_a_enr->getUDPAddress());
    a_ping_b_unauth_msg->attach(b_session);

    ASSERT_EQ(a_ping_b_unauth_msg->isValid(), true);
    ASSERT_EQ(a_ping_b_unauth_msg->getFlag(), DiscV5UnauthMessage::Flag::ORDINARY);
    ASSERT_EQ(a_ping_b_unauth_msg->getNonce(), ByteStream("0xffffffffffffffffffffffff", 12, 16));
    ASSERT_EQ(a_ping_b_unauth_msg->getAuthDataSize(), 32);

    auto a_ping_b_auth_msg = make_shared<const DiscV5AuthMessage>(a_ping_b_unauth_msg);
    ASSERT_EQ(a_ping_b_auth_msg->getSourceID(), node_a_enr->getID());
    ASSERT_EQ(a_ping_b_auth_msg->getType(), 1);

    auto a_ping_b_msg = make_shared<const DiscV5PingMessage>(a_ping_b_auth_msg);
    ASSERT_EQ(a_ping_b_msg->getRequestID(), 1);
    ASSERT_EQ(a_ping_b_msg->getENRSeq(), 2);
}

TEST(DiscV5_tests, DiscV5_p2p_ordinary_ping)
{
    auto node_a_enr = make_shared<const ENRV4Identity>(0, NODE_A_IP, NODE_A_UDP_PORT, NODE_A_TCP_PORT, NODE_A_SECRET);
    auto udp_server_a = make_shared<DiscV5Server>(node_a_enr);
    
    auto node_b_enr = make_shared<const ENRV4Identity>(0, NODE_B_IP, NODE_B_UDP_PORT, NODE_B_TCP_PORT, NODE_B_SECRET);
    auto udp_server_b = make_shared<DiscV5Server>(node_b_enr);

    // On the send-side (a)
    auto a_session = make_shared<DiscV5Session>(udp_server_a, node_b_enr->getUDPAddress(), node_b_enr->getID());
    a_session->updatePeerENR(node_b_enr);
    //We assume here that the session keys have already been negociated
    a_session->setHostSessionKey(ByteStream("0x00112233445566778899AABBCCDDEEFF", 16, 16));
    auto a_ping_b_sent_msg = make_shared<const DiscV5PingMessage>(a_session, DiscV5PingMessage::Flag::ORDINARY, 77);

    // On the receiving-side (b)
    auto b_session = make_shared<DiscV5Session>(udp_server_b, node_a_enr->getUDPAddress(), node_a_enr->getID());
    b_session->updatePeerENR(node_a_enr);
    //We assume here that the session keys have already been negociated
    b_session->setPeerSessionKey(ByteStream("0x00112233445566778899AABBCCDDEEFF", 16, 16));
    auto a_ping_b_received_unauth_msg = make_shared<DiscV5UnauthMessage>( udp_server_b,
                                                                          *a_ping_b_sent_msg.get(),
                                                                          node_a_enr->getUDPAddress());
    a_ping_b_received_unauth_msg->attach(b_session);
    auto a_ping_b_received_auth_msg = make_shared<const DiscV5AuthMessage>(a_ping_b_received_unauth_msg);
    auto a_ping_b_received_msg = make_shared<const DiscV5PingMessage>(a_ping_b_received_auth_msg);
    
    ASSERT_EQ(a_ping_b_received_msg->getMaskingIV(), a_ping_b_sent_msg->getMaskingIV());
    
    ASSERT_EQ(a_ping_b_received_msg->getMaskedHeader(), a_ping_b_sent_msg->getMaskedHeader());
    ASSERT_EQ(a_ping_b_received_msg->getHeader(), a_ping_b_sent_msg->getHeader());
    ASSERT_EQ(a_ping_b_received_msg->getProtocol(), "discv5");
    ASSERT_EQ(a_ping_b_received_msg->getVersion(), 1);
    ASSERT_EQ(a_ping_b_received_msg->getFlag(), DiscV5PingMessage::Flag::ORDINARY);
    ASSERT_EQ(a_ping_b_received_msg->getAuthDataSize(), 32);
    ASSERT_EQ(a_ping_b_received_msg->getSourceID(), node_a_enr->getID());
    
    ASSERT_EQ(a_ping_b_received_msg->getType(), 1);
    
    ASSERT_EQ(a_ping_b_received_msg->getRLPPayload(), a_ping_b_sent_msg->getRLPPayload());
    ASSERT_EQ(a_ping_b_received_msg->getRequestID(), 77);
    ASSERT_EQ(a_ping_b_received_msg->getENRSeq(), node_a_enr->getSeq());
}

TEST(DiscV5_tests, DiscV5_ingress_whoareyou)
{
    //https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire-test-vectors.md

    auto node_a_enr = make_shared<const ENRV4Identity>(0, NODE_A_IP, NODE_A_UDP_PORT, NODE_A_TCP_PORT, NODE_A_SECRET);
    auto udp_server_a = make_shared<DiscV5Server>(node_a_enr);
    
    auto node_b_enr = make_shared<const ENRV4Identity>(0, NODE_B_IP, NODE_B_UDP_PORT, NODE_B_TCP_PORT, NODE_B_SECRET);
    auto udp_server_b = make_shared<DiscV5Server>(node_b_enr);

    //Msg received by b
    auto b_session = make_shared<DiscV5Session>(udp_server_b, node_a_enr->getUDPAddress(), node_a_enr->getID());
    b_session->updatePeerENR(node_a_enr);
    auto a_ping_b_unauth_msg = make_shared<DiscV5UnauthMessage>( udp_server_b,
                                                                 ByteStream("00000000000000000000000000000000088b3d434277464933a1ccc59f5967ad1d6035f15e528627dde75cd68292f9e6c27d6b66c8100a873fcbaed4e16b8d", 63, 16),
                                                                 node_a_enr->getUDPAddress());
    a_ping_b_unauth_msg->attach(b_session);

    ASSERT_EQ(a_ping_b_unauth_msg->isValid(), true);
    ASSERT_EQ(a_ping_b_unauth_msg->getFlag(), DiscV5UnauthMessage::Flag::WHOAREYOU);
    ASSERT_EQ(a_ping_b_unauth_msg->getNonce(), ByteStream("0x0102030405060708090a0b0c", 12, 16));
    ASSERT_EQ(a_ping_b_unauth_msg->getAuthDataSize(), 24);

    auto a_ping_b_msg = make_shared<const DiscV5WhoAreYouMessage>(a_ping_b_unauth_msg);
    ASSERT_EQ(a_ping_b_msg->getChallengeData(), ByteStream("0x000000000000000000000000000000006469736376350001010102030405060708090a0b0c00180102030405060708090a0b0c0d0e0f100000000000000000", 63, 16));
    ASSERT_EQ(a_ping_b_msg->getIDNonce(), ByteStream("0x0102030405060708090a0b0c0d0e0f10", 16, 16));
    ASSERT_EQ(a_ping_b_msg->getENRSeq(), 0);    // 0 is the correct test value
}

TEST(DiscV5_tests, DiscV5_p2p_whoareyou)
{
    auto node_a_enr = make_shared<const ENRV4Identity>(0, NODE_A_IP, NODE_A_UDP_PORT, NODE_A_TCP_PORT, NODE_A_SECRET);
    auto udp_server_a = make_shared<DiscV5Server>(node_a_enr);
    
    auto node_b_enr = make_shared<const ENRV4Identity>(0, NODE_B_IP, NODE_B_UDP_PORT, NODE_B_TCP_PORT, NODE_B_SECRET);
    auto udp_server_b = make_shared<DiscV5Server>(node_b_enr);

    // On the send-side (a)
    auto a_session = make_shared<DiscV5Session>(udp_server_a, node_b_enr->getUDPAddress(), node_b_enr->getID());
    a_session->updatePeerENR(node_b_enr); 
    auto a_way_b_sent_msg = make_shared<const DiscV5WhoAreYouMessage>(a_session, ByteStream::generateRandom(12));

    // On the receiving-side (b)
    auto b_session = make_shared<DiscV5Session>(udp_server_b, node_a_enr->getUDPAddress(), node_a_enr->getID());
    b_session->updatePeerENR(node_a_enr);
    auto a_ping_b_unauth_msg = make_shared<DiscV5UnauthMessage>( udp_server_b,
                                                                 *a_way_b_sent_msg.get(),
                                                                 node_a_enr->getUDPAddress());
    a_ping_b_unauth_msg->attach(b_session);
    auto a_way_b_received_msg = make_shared<const DiscV5WhoAreYouMessage>(a_ping_b_unauth_msg);
    
    ASSERT_EQ(a_way_b_received_msg->getMaskingIV(), a_way_b_sent_msg->getMaskingIV());
    
    ASSERT_EQ(a_way_b_received_msg->getMaskedHeader(), a_way_b_sent_msg->getMaskedHeader());
    ASSERT_EQ(a_way_b_received_msg->getHeader(), a_way_b_sent_msg->getHeader());
    ASSERT_EQ(a_way_b_received_msg->getProtocol(), "discv5");
    ASSERT_EQ(a_way_b_received_msg->getVersion(), 1);
    ASSERT_EQ(a_way_b_received_msg->getFlag(), DiscV5PingMessage::Flag::WHOAREYOU);
    ASSERT_EQ(a_way_b_received_msg->getAuthDataSize(), 24);
        
    ASSERT_EQ(a_way_b_received_msg->getIDNonce(), a_way_b_sent_msg->getIDNonce());
    ASSERT_EQ(a_way_b_received_msg->getENRSeq(), b_session->getENR()->getSeq());

    //Check the correct registration of the ChallengeData by the sessions
    ASSERT_EQ(a_way_b_received_msg->getChallengeData(), a_way_b_sent_msg->getChallengeData());
}

TEST(DiscV5_tests, DiscV5_ingress_handshake_ping)
{
    //https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire-test-vectors.md

    auto node_a_enr = make_shared<const ENRV4Identity>(0, NODE_A_IP, NODE_A_UDP_PORT, NODE_A_TCP_PORT, NODE_A_SECRET);
    auto udp_server_a = make_shared<DiscV5Server>(node_a_enr);
    
    auto node_b_enr = make_shared<const ENRV4Identity>(0, NODE_B_IP, NODE_B_UDP_PORT, NODE_B_TCP_PORT, NODE_B_SECRET);
    auto udp_server_b = make_shared<DiscV5Server>(node_b_enr);

    //Msg received by b
    auto b_session = make_shared<DiscV5Session>(udp_server_b, node_a_enr->getUDPAddress(), node_a_enr->getID());
    b_session->updatePeerENR(node_a_enr);
    b_session->setLastSentChallengeData(ByteStream("0x000000000000000000000000000000006469736376350001010102030405060708090a0b0c00180102030405060708090a0b0c0d0e0f100000000000000001", 63, 16));
    auto a_ping_b_unauth_msg = make_shared<DiscV5UnauthMessage>( udp_server_b,
                                                                 ByteStream("0x00000000000000000000000000000000088b3d4342774649305f313964a39e55ea96c005ad521d8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d34c4f53245d08da4bb252012b2cba3f4f374a90a75cff91f142fa9be3e0a5f3ef268ccb9065aeecfd67a999e7fdc137e062b2ec4a0eb92947f0d9a74bfbf44dfba776b21301f8b65efd5796706adff216ab862a9186875f9494150c4ae06fa4d1f0396c93f215fa4ef524f1eadf5f0f4126b79336671cbcf7a885b1f8bd2a5d839cf8", 194, 16),
                                                                 node_a_enr->getUDPAddress() );
    a_ping_b_unauth_msg->attach(b_session);

    ASSERT_EQ(a_ping_b_unauth_msg->isValid(), true);
    ASSERT_EQ(a_ping_b_unauth_msg->getFlag(), DiscV5UnauthMessage::Flag::HANDSHAKE);
    ASSERT_EQ(a_ping_b_unauth_msg->getNonce(), ByteStream("0xffffffffffffffffffffffff", 12, 16));
    ASSERT_EQ(a_ping_b_unauth_msg->getAuthDataSize(), 131);

    auto a_ping_b_auth_msg = make_shared<const DiscV5AuthMessage>(a_ping_b_unauth_msg);

    //Verify the correct extraction of the session key from the handshake extra data
    ByteStream read_key("0x4f9fac6de7567d1e3b1241dffe90f662", 16, 16);
    ASSERT_EQ(b_session->getPeerSessionKey(), read_key);

    ASSERT_EQ(a_ping_b_auth_msg->getIDSignatureSize(), 64);
    ASSERT_EQ(a_ping_b_auth_msg->getEphemeralPubKeySize(), 33);
    ASSERT_EQ(a_ping_b_auth_msg->getIDSignature(), ByteStream("0xc0a04b36f276172afc66a62848eb0769800c670c4edbefab8f26785e7fda6b56506a3f27ca72a75b106edd392a2cbf8a69272f5c1785c36d1de9d98a0894b2db", 64, 16));
    ASSERT_EQ(a_ping_b_auth_msg->getEphemeralPubKey(), Pubkey(ByteStream("0x039a003ba6517b473fa0cd74aefe99dadfdb34627f90fec6362df85803908f53a5", 33, 16), Pubkey::Format::PREFIXED_X));

    ASSERT_EQ(a_ping_b_auth_msg->getSourceID(), node_a_enr->getID());
    ASSERT_EQ(a_ping_b_auth_msg->getType(), 1);

    auto a_ping_b_msg = make_shared<const DiscV5PingMessage>(a_ping_b_auth_msg);
    ASSERT_EQ(a_ping_b_msg->getRequestID(), 1);
    ASSERT_EQ(a_ping_b_msg->getENRSeq(), 1);
}

TEST(DiscV5_tests, DiscV5_ingress_handshake_ping_with_enr)
{
    //https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire-test-vectors.md

    auto node_a_enr = make_shared<const ENRV4Identity>(1, 0x7F000001, 24929, 12900, NODE_A_SECRET);
    auto udp_server_a = make_shared<DiscV5Server>(node_a_enr);
    
    auto node_b_enr = make_shared<const ENRV4Identity>(0, NODE_B_IP, NODE_B_UDP_PORT, NODE_B_TCP_PORT, NODE_B_SECRET);
    auto udp_server_b = make_shared<DiscV5Server>(node_b_enr);
  
    //Msg received by b
    auto b_session = make_shared<DiscV5Session>(udp_server_b, node_a_enr->getUDPAddress(), node_a_enr->getID());
    b_session->updatePeerENR(node_a_enr);
    b_session->setLastSentChallengeData(ByteStream("0x000000000000000000000000000000006469736376350001010102030405060708090a0b0c00180102030405060708090a0b0c0d0e0f100000000000000000", 63, 16));
    auto a_ping_b_unauth_msg = make_shared<DiscV5UnauthMessage>( udp_server_b,
                                                                 ByteStream("0x00000000000000000000000000000000088b3d4342774649305f313964a39e55ea96c005ad539c8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d34c4f53245d08da4bb23698868350aaad22e3ab8dd034f548a1c43cd246be98562fafa0a1fa86d8e7a3b95ae78cc2b988ded6a5b59eb83ad58097252188b902b21481e30e5e285f19735796706adff216ab862a9186875f9494150c4ae06fa4d1f0396c93f215fa4ef524e0ed04c3c21e39b1868e1ca8105e585ec17315e755e6cfc4dd6cb7fd8e1a1f55e49b4b5eb024221482105346f3c82b15fdaae36a3bb12a494683b4a3c7f2ae41306252fed84785e2bbff3b022812d0882f06978df84a80d443972213342d04b9048fc3b1d5fcb1df0f822152eced6da4d3f6df27e70e4539717307a0208cd208d65093ccab5aa596a34d7511401987662d8cf62b139471", 321, 16),
                                                                 node_a_enr->getUDPAddress());
    a_ping_b_unauth_msg->attach(b_session);

    ASSERT_EQ(a_ping_b_unauth_msg->isValid(), true);
    ASSERT_EQ(a_ping_b_unauth_msg->getFlag(), DiscV5UnauthMessage::Flag::HANDSHAKE);
    ASSERT_EQ(a_ping_b_unauth_msg->getNonce(), ByteStream("0xffffffffffffffffffffffff", 12, 16));
    ASSERT_EQ(a_ping_b_unauth_msg->getAuthDataSize(), 258);

    auto a_ping_b_auth_msg = make_shared<const DiscV5AuthMessage>(a_ping_b_unauth_msg);

    //Verify the correct extraction of the session key from the handshake extra data
    ByteStream read_key("0x53b1c075f41876423154e157470c2f48", 16, 16);
    ASSERT_EQ(b_session->getPeerSessionKey(), read_key);

    ASSERT_EQ(a_ping_b_auth_msg->getIDSignatureSize(), 64);
    ASSERT_EQ(a_ping_b_auth_msg->getEphemeralPubKeySize(), 33);
    ASSERT_EQ(a_ping_b_auth_msg->getIDSignature(), ByteStream("0xa439e69918e3f53f555d8ca4838fbe8abeab56aa55b056a2ac4d49c157ee719240a93f56c9fccfe7742722a92b3f2dfa27a5452f5aca8adeeab8c4d5d87df555", 64, 16));
    ASSERT_EQ(a_ping_b_auth_msg->getEphemeralPubKey(), Pubkey(ByteStream("0x039a003ba6517b473fa0cd74aefe99dadfdb34627f90fec6362df85803908f53a5", 33, 16), Pubkey::Format::PREFIXED_X));

    ASSERT_EQ(a_ping_b_auth_msg->getENR()->getName(), "enr:-H24QBfhsHORjaMtZAZCx2LA4ngWmOSXH4qzmnd0atrYPwHnb_yHTFkkgIu-fFCJCILCuKASh6CwgxLR1ToX1Rf16ycBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQMT0UIR4Ch7I2GhYViQqbUhIIBUbQoleuTP-Wz1NJksuQ");
    ASSERT_EQ(a_ping_b_auth_msg->getENR()->getScheme(), node_a_enr->getScheme());
    ASSERT_EQ(a_ping_b_auth_msg->getENR()->getPubKey(), node_a_enr->getPubKey());
    ASSERT_EQ(a_ping_b_auth_msg->getENR()->getID(), node_a_enr->getID());
    ASSERT_EQ(a_ping_b_auth_msg->getENR()->getSeq(), node_a_enr->getSeq());
    ASSERT_EQ(a_ping_b_auth_msg->getENR()->getIP(), node_a_enr->getIP());
    ASSERT_EQ(a_ping_b_auth_msg->getENR()->getUDPPort(), node_a_enr->getUDPPort());
    ASSERT_EQ(a_ping_b_auth_msg->getENR()->getTCPPort(), node_a_enr->getTCPPort());

    ASSERT_EQ(a_ping_b_auth_msg->getSourceID(), node_a_enr->getID());
    ASSERT_EQ(a_ping_b_auth_msg->getType(), 1);

    auto a_ping_b_msg = make_shared<const DiscV5PingMessage>(a_ping_b_auth_msg);
    ASSERT_EQ(a_ping_b_msg->getRequestID(), 1);
    ASSERT_EQ(a_ping_b_msg->getENRSeq(), 1);
}

TEST(DiscV5_tests, DiscV5_p2p_handshake_ping_with_enr)
{
    auto node_a_enr = make_shared<const ENRV4Identity>(0, NODE_A_IP, NODE_A_UDP_PORT, NODE_A_TCP_PORT, NODE_A_SECRET);
    auto udp_server_a = make_shared<DiscV5Server>(node_a_enr);
    
    auto node_b_enr = make_shared<const ENRV4Identity>(0, NODE_B_IP, NODE_B_UDP_PORT, NODE_B_TCP_PORT, NODE_B_SECRET);
    auto udp_server_b = make_shared<DiscV5Server>(node_b_enr);

    // On the send-side (a)
    auto a_session = make_shared<DiscV5Session>(udp_server_a, node_b_enr->getUDPAddress(), node_b_enr->getID());
    a_session->updatePeerENR(node_b_enr);
    a_session->setLastReceivedChallengeData(ByteStream("0x000000000000000000000000000000006469736376350001010102030405060708090a0b0c00180102030405060708090a0b0c0d0e0f100000000000000001", 63, 16));
    auto a_ping_b_sent_msg = make_shared<const DiscV5PingMessage>(a_session, DiscV5PingMessage::Flag::HANDSHAKE, 77);

    // On the receiving-side (b)
    auto b_session = make_shared<DiscV5Session>(udp_server_b, node_a_enr->getUDPAddress(), node_a_enr->getID());
    b_session->updatePeerENR(node_a_enr);
    b_session->setLastSentChallengeData(ByteStream("0x000000000000000000000000000000006469736376350001010102030405060708090a0b0c00180102030405060708090a0b0c0d0e0f100000000000000001", 63, 16));
    auto a_ping_b_received_unauth_msg = make_shared<DiscV5UnauthMessage>( udp_server_b,
                                                                          *a_ping_b_sent_msg.get(),
                                                                          node_a_enr->getUDPAddress());
    a_ping_b_received_unauth_msg->attach(b_session);
    
    auto a_ping_b_received_auth_msg = make_shared<const DiscV5AuthMessage>(a_ping_b_received_unauth_msg);

    //Verify the correct extraction of the session key from the handshake extra data
    ASSERT_EQ(b_session->getHostSessionKey(), a_session->getPeerSessionKey());
    ASSERT_EQ(b_session->getPeerSessionKey(), a_session->getHostSessionKey());

    auto a_ping_b_received_msg = make_shared<const DiscV5PingMessage>(a_ping_b_received_auth_msg);
    
    ASSERT_EQ(a_ping_b_received_msg->getMaskingIV(), a_ping_b_sent_msg->getMaskingIV());
    
    ASSERT_EQ(a_ping_b_received_msg->getMaskedHeader(), a_ping_b_sent_msg->getMaskedHeader());
    ASSERT_EQ(a_ping_b_received_msg->getHeader(), a_ping_b_sent_msg->getHeader());
    ASSERT_EQ(a_ping_b_received_msg->getProtocol(), "discv5");
    ASSERT_EQ(a_ping_b_received_msg->getVersion(), 1);
    ASSERT_EQ(a_ping_b_received_msg->getFlag(), DiscV5PingMessage::Flag::HANDSHAKE);
    ASSERT_EQ(a_ping_b_received_msg->getAuthDataSize(), 34 + 64 + 33 + a_ping_b_received_msg->getENR()->getSignedRLP().byteSize() );
    ASSERT_EQ(a_ping_b_received_msg->getSourceID(), node_a_enr->getID());
    ASSERT_EQ(a_ping_b_received_msg->getIDSignatureSize(), 64);
    ASSERT_EQ(a_ping_b_received_msg->getEphemeralPubKeySize(), 33);
    
    ASSERT_EQ(a_ping_b_received_msg->getMessageData(), a_ping_b_sent_msg->getMessageData());
    ASSERT_EQ(a_ping_b_received_msg->getType(), 1);
    
    ASSERT_EQ(a_ping_b_received_msg->getRLPPayload(), a_ping_b_sent_msg->getRLPPayload());
    ASSERT_EQ(a_ping_b_received_msg->getRequestID(), 77);
    ASSERT_EQ(a_ping_b_received_msg->getENRSeq(), b_session->getENR()->getSeq());
}
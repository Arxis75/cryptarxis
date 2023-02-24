#include "Network.h"

#include <p2p/DiscV4.h>
#include <p2p/DiscV4Msg.h>

#include <iostream>         //cout

using std::cout;
using std::hex;
using std::dec;
using std::endl;
using std::dynamic_pointer_cast;

#define EXPIRATION_DELAY_IN_SEC 20

DiscV4SignedMessage::DiscV4SignedMessage(const shared_ptr<const DiscV4SignedMessage> signed_msg)
    : DiscoveryMessage(signed_msg)
    , m_hash(signed_msg->m_hash)
    , m_pub_key(signed_msg->m_pub_key)
    , m_hashed_payload(signed_msg->m_hashed_payload)
    , m_signed_payload(signed_msg->m_signed_payload)
    , m_ID(signed_msg->m_ID)
    , m_type(signed_msg->m_type)
    , m_rlp_payload(signed_msg->m_rlp_payload)
{ }

DiscV4SignedMessage::DiscV4SignedMessage(const vector<uint8_t> &buffer)
    : DiscoveryMessage(buffer)
{
    if( hasValidSize() )
    {
        m_hash = ByteStream(&buffer[0], 32);
        m_hashed_payload = ByteStream(&buffer[32], size() - 32);
        m_signed_payload = ByteStream(&buffer[97], size() - 97);
        Signature sig(ByteStream(&buffer[32], 32).as_Integer(), ByteStream(&buffer[64], 32).as_Integer(), ByteStream(&buffer[96], 1).as_bool());
        sig.ecrecover(m_pub_key, m_signed_payload.keccak256());
        m_ID = m_pub_key.getID();
        m_type = ByteStream(&buffer[97], 1).as_uint8();
        m_rlp_payload = RLPByteStream(&buffer[98], size() - 98);
    }
}

DiscV4SignedMessage::DiscV4SignedMessage(const shared_ptr<const SessionHandler> session_handler)
    : DiscoveryMessage(session_handler)
    , m_ID(ByteStream(session_handler->getPeerID()))
{
}

void DiscV4SignedMessage::addTypeSignAndHash(const RLPByteStream &rlp_payload)
{
    m_rlp_payload = rlp_payload;
    m_type = getType();
    ByteStream signed_msg = m_rlp_payload;
    signed_msg.push_front(m_type, 1); //no RLP-encoding for the type
    m_signed_payload = signed_msg;
    m_pub_key = getHostENR()->getSecret()->getPubKey();
    m_ID = m_pub_key.getID();
    Signature sig = getHostENR()->getSecret()->sign(signed_msg.keccak256());
    signed_msg.push_front(ByteStream(sig.get_imparity(), 1));
    signed_msg.push_front(ByteStream(sig.get_s(), 32));
    signed_msg.push_front(ByteStream(sig.get_r(), 32));
    m_hashed_payload = signed_msg;
    m_hash = m_hashed_payload.keccak256();
    signed_msg.push_front(m_hash);

    clear();
    push_back(signed_msg);
}

const string DiscV4SignedMessage::getName() const
{
    string retval;
    switch( getType() )
    {
    case 0x01:
        return "PING";
    case 0x02:
        return "PONG";
    case 0x03:
        return "FINDNODE";
    case 0x04:
        return "NEIGHBORS";
    case 0x05:
        return "ENRREQUEST";
    case 0x06:
        return "ENRRESPONSE";
    default:
        return "UNKNOWN";
    }
}

void DiscV4SignedMessage::print() const
{
    cout << dec << "   @UDP DiscV4 " << getName() << " MESSAGE:" <<endl;
    
    //SocketMessage::print();   // Printing raw byteStream
    
    cout << "   Size : " << dec << size() << endl;
    cout << "   Hash = " << hex << getHash().as_Integer() << endl;
    cout << "   Public key = " << hex << getPubKey().getKey(Pubkey::Format::PREFIXED_X).as_Integer() << endl;
    cout << "   ID = " << hex << ByteStream(getPeerID()) << endl;
    cout << "   Type = " << dec << int(getType()) << endl;
};

//-----------------------------------------------------------------------------------------------------

DiscV4PingMessage::DiscV4PingMessage(const shared_ptr<const SessionHandler> session_handler)
    : DiscV4SignedMessage(session_handler)
    , m_version(4)
    , m_sender_ip(getHostENR()->getIP())
    , m_sender_udp_port(getHostENR()->getUDPPort())
    , m_sender_tcp_port(getHostENR()->getTCPPort())
    , m_recipient_ip(ntohl(session_handler->getPeerAddress().sin_addr.s_addr))
    , m_recipient_udp_port(ntohs(session_handler->getPeerAddress().sin_port)) 
    , m_recipient_tcp_port(0) 
    , m_expiration(getUnixTimeStamp() + EXPIRATION_DELAY_IN_SEC)
    , m_enr_seq(getHostENR()->getSeq())
{
    RLPByteStream rlp, from, to;
    rlp.push_back(ByteStream(m_version));
    from.push_back(ByteStream(m_sender_ip));
    from.push_back(ByteStream(m_sender_udp_port));
    from.push_back(ByteStream(m_sender_tcp_port));
    rlp.push_back(from);
    to.push_back(ByteStream(m_recipient_ip));
    to.push_back(ByteStream(m_recipient_udp_port));
    to.push_back(ByteStream());
    rlp.push_back(to);
    rlp.push_back(ByteStream(m_expiration));
    rlp.push_back(ByteStream(m_enr_seq));
    
    addTypeSignAndHash(rlp);
}

DiscV4PingMessage::DiscV4PingMessage(const shared_ptr<const DiscV4SignedMessage> signed_msg)
    : DiscV4SignedMessage(signed_msg)
    , m_enr_seq(0)
{
    bool is_list;
    RLPByteStream rlp = getRLPPayload();

    m_version = rlp.pop_front(is_list).as_uint8();
    RLPByteStream from = rlp.pop_front(is_list);
    if( from.byteSize() > 1 )   //non-empty list
    {
        m_sender_ip = from.pop_front(is_list).as_uint64();
        m_sender_udp_port = from.pop_front(is_list).as_uint64(); 
        m_sender_tcp_port = from.pop_front(is_list).as_uint64(); 
    }
    RLPByteStream to = rlp.pop_front(is_list);
    if( to.byteSize() > 1 )     //non-empty list
    {
        m_recipient_ip = to.pop_front(is_list).as_uint64();
        m_recipient_udp_port = to.pop_front(is_list).as_uint64(); 
        m_recipient_tcp_port = to.pop_front(is_list).as_uint64(); 
    }
    m_expiration = rlp.pop_front(is_list).as_uint64();
    if( rlp.byteSize() > 0 )
        m_enr_seq = rlp.pop_front(is_list).as_uint64();
}

void DiscV4PingMessage::print() const
{
    DiscV4SignedMessage::print();
    if( hasExpired() )
        cout << dec << "   EXPIRED MESSAGE!" << endl;
    else
    {
        cout << "   Ping Hash = " << hex << getHash().as_Integer() << endl;
        cout << "   Version = " << dec << uint16_t(m_version) << endl;
        cout << "   Sender_ip = " << dec << ((m_sender_ip >> 24) & 0xFF) << "."
                                        << ((m_sender_ip >> 16) & 0xFF) << "." 
                                        << ((m_sender_ip >> 8) & 0xFF) << "." 
                                        << (m_sender_ip & 0xFF) << endl;
        cout << "   Sender_udp_port = " << dec << m_sender_udp_port << endl;
        cout << "   Sender_tcp_port = " << dec << m_sender_tcp_port << endl;
        cout << "   Recipient_ip = " << dec << ((m_recipient_ip >> 24) & 0xFF) << "."
                                            << ((m_recipient_ip >> 16) & 0xFF) << "." 
                                            << ((m_recipient_ip >> 8) & 0xFF) << "." 
                                            << (m_recipient_ip & 0xFF) << endl;
        cout << "   Recipient_udp_port = " << dec << m_recipient_udp_port << endl;
        cout << "   Recipient_tcp_port = " << dec << m_recipient_tcp_port << endl;
        cout << "   Expiration = " << dec << m_expiration << ", Now is " << getUnixTimeStamp() << endl;
        if( m_enr_seq )
            cout << "   ENR-seq = " << dec << m_enr_seq << endl;
    }
}

//-----------------------------------------------------------------------------------------------------

DiscV4PongMessage::DiscV4PongMessage(const shared_ptr<const SessionHandler> session_handler, const ByteStream &ack_hash)
    : DiscV4SignedMessage(session_handler)
    , m_recipient_ip(ntohl(session_handler->getPeerAddress().sin_addr.s_addr))
    , m_recipient_udp_port(ntohs(session_handler->getPeerAddress().sin_port)) 
    , m_recipient_tcp_port(0) 
    , m_ping_hash(ack_hash)
    , m_expiration(getUnixTimeStamp() + EXPIRATION_DELAY_IN_SEC)
    , m_enr_seq(getHostENR()->getSeq())
{
    RLPByteStream to, rlp;
    to.push_back(ByteStream(m_recipient_ip));
    to.push_back(ByteStream(m_recipient_udp_port));
    to.push_back(ByteStream());
    rlp.push_back(to);
    rlp.push_back(m_ping_hash, true);
    rlp.push_back(ByteStream(m_expiration));
    rlp.push_back(ByteStream(m_enr_seq));
    addTypeSignAndHash(rlp);
}

DiscV4PongMessage::DiscV4PongMessage(const shared_ptr<const DiscV4SignedMessage> signed_msg)
    : DiscV4SignedMessage(signed_msg)
    , m_enr_seq(0)
{
    bool is_list;
    RLPByteStream rlp = getRLPPayload();

    RLPByteStream to = rlp.pop_front(is_list);
    if( to.byteSize() > 1 )     //non-empty list
    {
        m_recipient_ip = to.pop_front(is_list).as_uint64();
        m_recipient_udp_port = to.pop_front(is_list).as_uint64();
        m_recipient_tcp_port = to.pop_front(is_list).as_uint64();
    }
    m_ping_hash = rlp.pop_front(is_list);
    m_expiration = rlp.pop_front(is_list).as_uint64();
    if( rlp.byteSize() > 0 )
        m_enr_seq = rlp.pop_front(is_list).as_uint64();
}

void DiscV4PongMessage::print() const
{
    DiscV4SignedMessage::print();
    if( hasExpired() )
        cout << dec << "   EXPIRED MESSAGE!" << endl;
    else
    {
        cout << "   Recipient_ip = " << dec << ((m_recipient_ip >> 24) & 0xFF) << "."
                                            << ((m_recipient_ip >> 16) & 0xFF) << "." 
                                            << ((m_recipient_ip >> 8) & 0xFF) << "." 
                                            << (m_recipient_ip & 0xFF) << endl;
        cout << "   Recipient_udp_port = " << dec << m_recipient_udp_port << endl;
        cout << "   Recipient_tcp_port = " << dec << m_recipient_tcp_port << endl;
        cout << "   Ping Hash = " << hex << m_ping_hash.as_Integer() << endl;
        cout << "   Expiration = " << dec << m_expiration << ", Now is " << getUnixTimeStamp() << endl;
        if( m_enr_seq )
            cout << "   ENR-seq = " << dec << m_enr_seq << endl;
    }
}

//-----------------------------------------------------------------------------------------------------

DiscV4FindNodeMessage::DiscV4FindNodeMessage(const shared_ptr<const SessionHandler> session_handler)
    : DiscV4SignedMessage(session_handler)
    , m_target(getHostENR()->getPubKey())
    , m_expiration(getUnixTimeStamp() + EXPIRATION_DELAY_IN_SEC)
{
    RLPByteStream rlp;
    rlp.push_back(m_target.getKey(Pubkey::Format::XY));
    rlp.push_back(ByteStream(m_expiration));
    addTypeSignAndHash(rlp);
}

DiscV4FindNodeMessage::DiscV4FindNodeMessage(const shared_ptr<const DiscV4SignedMessage> signed_msg)
    : DiscV4SignedMessage(signed_msg)
{
    bool is_list;
    RLPByteStream rlp = getRLPPayload();

    m_target = Pubkey(rlp.pop_front(is_list), Pubkey::Format::XY);
    m_expiration = rlp.pop_front(is_list).as_uint64();
}

void DiscV4FindNodeMessage::print() const
{
    DiscV4SignedMessage::print();
    if( hasExpired() )
        cout << dec << "   EXPIRED MESSAGE!" << endl;
    else
    {
        cout << "   Target = 0x" << hex << m_target.getKey(Pubkey::Format::XY) << endl;
        cout << "   Expiration = " << dec << m_expiration << ", Now is " << getUnixTimeStamp() << endl;
    }
}

//-----------------------------------------------------------------------------------------------------

DiscV4NeighborsMessage::DiscV4NeighborsMessage(const shared_ptr<const SessionHandler> session_handler, const vector<shared_ptr<const ENRV4Identity>> &neighbors_enr)
    : DiscV4SignedMessage(session_handler)
    , m_nodes(neighbors_enr)
    , m_expiration(getUnixTimeStamp() + EXPIRATION_DELAY_IN_SEC)
{
    RLPByteStream rlp(ByteStream(), true);
    
    for(auto it = neighbors_enr.begin(); it != neighbors_enr.end(); it++)
    {
        RLPByteStream node_i;
        if( auto node = it->get() )
        {
            node_i.push_back(node->getIP() ? ByteStream(node->getIP()) : ByteStream());           //Transmit empty instead of 0
            node_i.push_back(node->getUDPPort() ? ByteStream(node->getUDPPort()) : ByteStream()); //Transmit empty instead of 0
            node_i.push_back(node->getTCPPort() ? ByteStream(node->getTCPPort()) : ByteStream()); //Transmit empty instead of 0
            node_i.push_back(node->getPubKey().getKey(Pubkey::Format::XY));
        }
        rlp.push_back(node_i);
    }

    rlp.push_back(ByteStream(m_expiration), true);
    addTypeSignAndHash(rlp);
    //cout << hex << rlp.as_Integer() << endl;
}

DiscV4NeighborsMessage::DiscV4NeighborsMessage(const shared_ptr<const DiscV4SignedMessage> signed_msg)
    : DiscV4SignedMessage(signed_msg)
{
    bool is_list;
    RLPByteStream rlp = getRLPPayload();

    RLPByteStream node_list = rlp.pop_front(is_list);
    while( node_list.byteSize() )
    {
        RLPByteStream node_i = node_list.pop_front(is_list);
        if( node_i.byteSize() > 1 )     // if list is not empty
        {
            uint32_t node_ip = node_i.pop_front(is_list).as_uint64();
            uint16_t node_udp_port = node_i.pop_front(is_list).as_uint64();
            uint16_t node_tcp_port = node_i.pop_front(is_list).as_uint64();
            Pubkey node_pub_key(node_i.pop_front(is_list), Pubkey::Format::XY);
        
            m_nodes.push_back(make_shared<const ENRV4Identity>(0, node_ip, node_udp_port, node_tcp_port, node_pub_key));
        }
    }

    m_expiration = rlp.pop_front(is_list).as_uint64();
}

void DiscV4NeighborsMessage::print() const
{
    DiscV4SignedMessage::print();
    if( hasExpired() )
        cout << dec << "   EXPIRED MESSAGE!" << endl;
    else
    {
        auto nodes(m_nodes);
        while( nodes.size() )
        {
            if( auto node_i = nodes.back() ) 
            {
                cout << "   ----------------------------------------" << endl;
                cout << "   Node IP = " << dec << ((node_i->getIP() >> 24) & 0xFF) << "."
                                                << ((node_i->getIP() >> 16) & 0xFF) << "." 
                                                << ((node_i->getIP() >> 8) & 0xFF) << "." 
                                                << (node_i->getIP() & 0xFF) << endl;
                cout << "   Node UDP PORT = " << dec << node_i->getUDPPort() << endl;
                cout << "   Node TCP PORT = " << dec << node_i->getTCPPort() << endl;
                cout << "   Node PUBLIC KEY = 0x" << hex << node_i->getPubKey().getKey(Pubkey::Format::PREFIXED_X) << endl;
                cout << "   Node ID = 0x" << hex << node_i->getPubKey().getKey(Pubkey::Format::XY).keccak256() << endl;
            }

            nodes.pop_back();    // => next node
        }
        cout << "   ----------------------------------------" << endl;
        cout << "   Expiration = " << dec << m_expiration << ", Now is " << getUnixTimeStamp() << endl;
    }
}

//-----------------------------------------------------------------------------------------------------

DiscV4ENRRequestMessage::DiscV4ENRRequestMessage(const shared_ptr<const SessionHandler> session_handler)
    : DiscV4SignedMessage(session_handler)
    , m_expiration(getUnixTimeStamp() + EXPIRATION_DELAY_IN_SEC)
{
    RLPByteStream rlp(RLPByteStream(m_expiration), true);
    addTypeSignAndHash(rlp);
}

DiscV4ENRRequestMessage::DiscV4ENRRequestMessage(const shared_ptr<const DiscV4SignedMessage> signed_msg)
    : DiscV4SignedMessage(signed_msg)
{
    bool is_list;
    RLPByteStream rlp = getRLPPayload();

    m_expiration = rlp.pop_front(is_list).as_uint64();
}

void DiscV4ENRRequestMessage::print() const
{
    DiscV4SignedMessage::print();
    if( hasExpired() )
        cout << dec << "   EXPIRED MESSAGE!" << endl;
    else
    {
        cout << "   Expiration = " << dec << m_expiration << ", Now is " << getUnixTimeStamp() << endl;
    }
}

//-----------------------------------------------------------------------------------------------------

DiscV4ENRResponseMessage::DiscV4ENRResponseMessage(const shared_ptr<const SessionHandler> session_handler, const ByteStream &ack_hash)
    : DiscV4SignedMessage(session_handler)
    , m_enr_request_hash(ack_hash)
    , m_sender_enr(getHostENR())
{
    RLPByteStream rlp;
    rlp.push_back(ack_hash);
    rlp.push_back(getHostENR()->getSignedRLP());
    addTypeSignAndHash(rlp);
}

DiscV4ENRResponseMessage::DiscV4ENRResponseMessage(const shared_ptr<const DiscV4SignedMessage> signed_msg)
    : DiscV4SignedMessage(signed_msg)
    , m_sender_enr(shared_ptr<const ENRV4Identity>(nullptr))
{
    bool is_list;
    if( auto ping_msg = dynamic_pointer_cast<const DiscV4PingMessage>(signed_msg) )
    {
        // DiscV4ENRResponseMessage emulated from DiscV4PingMessage
        // Relying on the session IP:Port over those of the ping limits IP spoofing...
        m_sender_enr = make_shared<const ENRV4Identity>( 0, // seq = 0 because this is not the actual record
                                                         ntohl(ping_msg->getSessionHandler()->getPeerAddress().sin_addr.s_addr),
                                                         ntohs(ping_msg->getSessionHandler()->getPeerAddress().sin_port),
                                                         ping_msg->getSenderTCPPort(),
                                                         ping_msg->getPubKey()
                                                        );
    }
    else
    {
        RLPByteStream rlp = getRLPPayload();

        m_enr_request_hash = rlp.pop_front(is_list);

        m_sender_enr = make_shared<const ENRV4Identity>(rlp.pop_front(is_list));
    }
}

void DiscV4ENRResponseMessage::print() const
{
    DiscV4SignedMessage::print();
    cout << dec << "   @UDP DiscV4 ENR RECORD:" << endl;
    cout << "   ENR Request hash = 0x" << hex << m_enr_request_hash.as_Integer() << endl;
    getENR()->print();
}
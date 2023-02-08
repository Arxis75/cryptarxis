#include "Network.h"
#include "DiscV4Msg.h"

#include <iostream>         //cout

using std::cout;
using std::hex;
using std::dec;
using std::endl;
using std::dynamic_pointer_cast;

#define EXPIRATION_DELAY_IN_SEC 20

DiscV4SignedMessage::DiscV4SignedMessage(const shared_ptr<const DiscV4SignedMessage> signed_msg)
    : SocketMessage(signed_msg->getSessionHandler())
    , m_vect(signed_msg->m_vect)
    , m_timestamp(getUnixTimeStamp())
{ }

DiscV4SignedMessage::DiscV4SignedMessage(const shared_ptr<const SessionHandler> session_handler)
    : SocketMessage(session_handler)
    , m_timestamp(getUnixTimeStamp())
{ }

const ByteStream DiscV4SignedMessage::getHash() const
{
    return ByteStream(&(*this)[0], 32);
}

const Pubkey DiscV4SignedMessage::getPubKey() const
{
    Pubkey pub_key;
    Signature sig(ByteStream(&(*this)[32], 32).as_Integer(), ByteStream(&(*this)[64], 32).as_Integer(), ByteStream(&(*this)[96], 1));
    sig.ecrecover(pub_key, getSignedPayload().keccak256());
    return pub_key;
}

const uint8_t DiscV4SignedMessage::getType() const
{
    return ByteStream(&(*this)[97], 1).as_uint8();
}

const ByteStream DiscV4SignedMessage::getSignedPayload() const
{
    return ByteStream(&(*this)[97], size() - 97);
}

const RLPByteStream DiscV4SignedMessage::getRLPPayload() const
{
    return RLPByteStream(&(*this)[98], size() - 98);
}

bool DiscV4SignedMessage::hasValidSize() const
{
    return size() > 98;
}

bool DiscV4SignedMessage::hasValidHash() const
{
    return getHash() == ByteStream(&(*this)[32], size() - 32).keccak256(); 
}

bool DiscV4SignedMessage::hasValidType(uint8_t &type) const
{
    type = getType();
    return type > 0 && type < 7;
}

uint64_t DiscV4SignedMessage::size() const
{
    return m_vect.size();
}

DiscV4SignedMessage::operator const uint8_t*() const
{
    return m_vect.data();
}

void DiscV4SignedMessage::push_back(const uint8_t value)
{ 
    m_vect.push_back(value);
}

void DiscV4SignedMessage::addTypeSignAndHash(const RLPByteStream &rlp_payload)
{
    ByteStream signed_msg = rlp_payload;
    signed_msg.push_front(getType(), 1); //no RLP-encoding for the type
    Signature sig = Network::GetInstance().getHostENR()->getSecret()->sign(signed_msg.keccak256());
    signed_msg.push_front(ByteStream(sig.get_imparity(), 1));
    signed_msg.push_front(ByteStream(sig.get_s(), 32));
    signed_msg.push_front(ByteStream(sig.get_r(), 32));
    signed_msg.push_front(signed_msg.keccak256());

    for(int i=0;i<signed_msg.byteSize();i++)
        push_back(signed_msg[i]);
}

//-----------------------------------------------------------------------------------------------------

DiscV4PingMessage::DiscV4PingMessage(const shared_ptr<const SessionHandler> session_handler)
    : DiscV4SignedMessage(session_handler)
    , m_version(4)
    , m_sender_ip(Network::GetInstance().getHostENR()->getIP())
    , m_sender_udp_port(Network::GetInstance().getHostENR()->getUDPPort())
    , m_sender_tcp_port(Network::GetInstance().getHostENR()->getTCPPort())
    , m_recipient_ip(htonl(session_handler->getPeerAddress().sin_addr.s_addr))
    , m_recipient_udp_port(htons(session_handler->getPeerAddress().sin_port)) 
    , m_recipient_tcp_port(0) 
    , m_expiration(getUnixTimeStamp() + EXPIRATION_DELAY_IN_SEC)
    , m_enr_seq(Network::GetInstance().getHostENR()->getSeq())
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
{
    bool is_list;
    RLPByteStream msg(&(*signed_msg)[0], signed_msg->size());

    //Drops the header:
    // - 32 bytes hash,
    // - 65 bytes signature,
    // - 1 byte type
    msg.ByteStream::pop_front(98);

    m_version = msg.pop_front(is_list).as_uint8();
    RLPByteStream from = msg.pop_front(is_list);
    m_sender_ip = from.pop_front(is_list).as_uint64();
    m_sender_udp_port = from.pop_front(is_list).as_uint64(); 
    m_sender_tcp_port = from.pop_front(is_list).as_uint64(); 
    RLPByteStream to = msg.pop_front(is_list);
    m_recipient_ip = to.pop_front(is_list).as_uint64();
    m_recipient_udp_port = to.pop_front(is_list).as_uint64(); 
    m_recipient_tcp_port = to.pop_front(is_list).as_uint64(); 
    m_expiration = msg.pop_front(is_list).as_uint64();
    m_enr_seq = msg.pop_front(is_list).as_uint64();
}

void DiscV4PingMessage::print() const
{
    if( !hasNotExpired() )
        cout << dec << "   @UDP DiscV4 EXPIRED PING" << endl;
    else
        cout << dec << "   @UDP DiscV4 PING" << endl;
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

//-----------------------------------------------------------------------------------------------------

DiscV4PongMessage::DiscV4PongMessage(const shared_ptr<const SessionHandler> session_handler, const ByteStream &ack_hash)
    : DiscV4SignedMessage(session_handler)
    , m_recipient_ip(htonl(session_handler->getPeerAddress().sin_addr.s_addr))
    , m_recipient_udp_port(htons(session_handler->getPeerAddress().sin_port)) 
    , m_recipient_tcp_port(0) 
    , m_ping_hash(ack_hash)
    , m_expiration(getUnixTimeStamp() + EXPIRATION_DELAY_IN_SEC)
    , m_enr_seq(Network::GetInstance().getHostENR()->getSeq())
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
{
    bool is_list;
    RLPByteStream msg(&(*signed_msg)[0], signed_msg->size());

    //Drops the header:
    // - 32 bytes hash,
    // - 65 bytes signature,
    // - 1 byte type
    msg.ByteStream::pop_front(98);

    RLPByteStream to = msg.pop_front(is_list);
    m_recipient_ip = to.pop_front(is_list).as_uint64();
    m_recipient_udp_port = to.pop_front(is_list).as_uint64(); 
    m_recipient_tcp_port = to.pop_front(is_list).as_uint64(); 
    m_ping_hash = msg.pop_front(is_list);
    m_expiration = msg.pop_front(is_list).as_uint64();
    m_enr_seq = msg.pop_front(is_list).as_uint64();
}

void DiscV4PongMessage::print() const
{
    auto session =  dynamic_pointer_cast<const DiscV4Session>(getSessionHandler());
    if( session )
    {
        auto server = dynamic_pointer_cast<const DiscV4Server>(session->getSocketHandler());
        if( server )
        {
            if( !hasNotExpired() )
                cout << dec << "   @UDP DiscV4 EXPIRED PONG" << endl;
            else
                cout << dec << "   @UDP DiscV4 PONG" << endl;
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
}

//-----------------------------------------------------------------------------------------------------

DiscV4FindNodeMessage::DiscV4FindNodeMessage(const shared_ptr<const SessionHandler> session_handler, const ByteStream &target)
    : DiscV4SignedMessage(session_handler)
    , m_target(target)
    , m_expiration(getUnixTimeStamp() + EXPIRATION_DELAY_IN_SEC)
{
    RLPByteStream rlp;
    rlp.push_back(m_target);
    rlp.push_back(ByteStream(m_expiration));
    addTypeSignAndHash(rlp);
}

DiscV4FindNodeMessage::DiscV4FindNodeMessage(const shared_ptr<const DiscV4SignedMessage> signed_msg)
    : DiscV4SignedMessage(signed_msg)
{
    bool is_list;
    RLPByteStream msg(&(*signed_msg)[0], signed_msg->size());

    //Drops the header:
    // - 32 bytes hash,
    // - 65 bytes signature,
    // - 1 byte type
    msg.ByteStream::pop_front(98);

    m_target = msg.pop_front(is_list);
    m_expiration = msg.pop_front(is_list).as_uint64();
}

void DiscV4FindNodeMessage::print() const
{
    auto session =  dynamic_pointer_cast<const DiscV4Session>(getSessionHandler());
    if( session )
    {
        auto server = dynamic_pointer_cast<const DiscV4Server>(session->getSocketHandler());
        if( server )
        {
            if( !hasNotExpired() )
                cout << dec << "   @UDP DiscV4 EXPIRED FINDNODE" << endl;
            else
                cout << dec << "   @UDP DiscV4 FINDNODE" << endl;
            cout << "   Target = 0x" << hex << m_target << endl;
            cout << "   Expiration = " << dec << m_expiration << ", Now is " << getUnixTimeStamp() << endl;
        }
    }
}

//-----------------------------------------------------------------------------------------------------

DiscV4NeighborsMessage::DiscV4NeighborsMessage(const shared_ptr<const SessionHandler> session_handler)
    : DiscV4SignedMessage(session_handler)
    , m_nodes(RLPByteStream(true))  //empty, FIXME!!!!
    , m_expiration(getUnixTimeStamp() + EXPIRATION_DELAY_IN_SEC)
{
    RLPByteStream rlp;
    rlp.push_back(m_nodes);
    rlp.push_back(ByteStream(m_expiration));
    addTypeSignAndHash(rlp);
}

DiscV4NeighborsMessage::DiscV4NeighborsMessage(const shared_ptr<const DiscV4SignedMessage> signed_msg)
    : DiscV4SignedMessage(signed_msg)
{
    bool is_list;
    RLPByteStream msg(&(*signed_msg)[0], signed_msg->size());

    //Drops the header:
    // - 32 bytes hash,
    // - 65 bytes signature,
    // - 1 byte type
    msg.ByteStream::pop_front(98);

    m_nodes = msg.pop_front(is_list);
    m_expiration = msg.pop_front(is_list).as_uint64();
}

void DiscV4NeighborsMessage::print() const
{
    auto session =  dynamic_pointer_cast<const DiscV4Session>(getSessionHandler());
    if( session )
    {
        auto server = dynamic_pointer_cast<const DiscV4Server>(session->getSocketHandler());
        if( server )
        {
            bool is_list;
            RLPByteStream nodes(m_nodes);

            if( !hasNotExpired() )
                cout << dec << "   @UDP DiscV4 EXPIRED NEIGHBORS" << endl;
            else
                cout << dec << "   @UDP DiscV4 NEIGHBORS" << endl;
            while( nodes.byteSize() > 1 )
            {
                RLPByteStream node_i = nodes.pop_front(is_list);
                uint32_t node_ip = node_i.pop_front(is_list).as_uint64();
                cout << "   ----------------------------------------" << endl;
                cout << "   Node IP = " << dec << ((node_ip >> 24) & 0xFF) << "."
                                                    << ((node_ip >> 16) & 0xFF) << "." 
                                                    << ((node_ip >> 8) & 0xFF) << "." 
                                                    << (node_ip & 0xFF) << endl;
                cout << "   Node UDP PORT = " << dec << node_i.pop_front(is_list).as_uint64() << endl;
                cout << "   Node TCP PORT = " << dec << node_i.pop_front(is_list).as_uint64() << endl;
                cout << "   Node PUBLIC KEY = 0x" << hex << node_i.pop_front(is_list) << endl;
            }
            cout << "   ----------------------------------------" << endl;
            cout << "   Expiration = " << dec << m_expiration << ", Now is " << getUnixTimeStamp() << endl;
        }
    }
}

//-----------------------------------------------------------------------------------------------------

DiscV4ENRRequestMessage::DiscV4ENRRequestMessage(const shared_ptr<const SessionHandler> session_handler)
    : DiscV4SignedMessage(session_handler)
    , m_expiration(getUnixTimeStamp() + EXPIRATION_DELAY_IN_SEC)
{
    RLPByteStream rlp;
    rlp.push_back(ByteStream(m_expiration));
    addTypeSignAndHash(rlp);
}

DiscV4ENRRequestMessage::DiscV4ENRRequestMessage(const shared_ptr<const DiscV4SignedMessage> signed_msg)
    : DiscV4SignedMessage(signed_msg)
{
    bool is_list;
    RLPByteStream msg(&(*signed_msg)[0], signed_msg->size());

    //Drops the header:
    // - 32 bytes hash,
    // - 65 bytes signature,
    // - 1 byte type
    msg.ByteStream::pop_front(98);

    m_expiration = msg.pop_front(is_list).as_uint64();
}

void DiscV4ENRRequestMessage::print() const
{
    auto session =  dynamic_pointer_cast<const DiscV4Session>(getSessionHandler());
    if( session )
    {
        auto server = dynamic_pointer_cast<const DiscV4Server>(session->getSocketHandler());
        if( server )
        {
            if( !hasNotExpired() )
                cout << dec << "   @UDP DiscV4 EXPIRED ENRREQUEST" << endl;
            else
                cout << dec << "   @UDP DiscV4 ENRREQUEST" << endl;
            cout << "   Expiration = " << dec << m_expiration << ", Now is " << getUnixTimeStamp() << endl;
        }
    }
}

//-----------------------------------------------------------------------------------------------------

DiscV4ENRResponseMessage::DiscV4ENRResponseMessage(const shared_ptr<const SessionHandler> session_handler, const ByteStream &ack_hash)
    : DiscV4SignedMessage(session_handler)
    , m_enr_request_hash(ack_hash)
    , m_sender_enr(Network::GetInstance().getHostENR())
/*    , m_sender_enr(new ENRV4Identity( Network::GetInstance().getHostENR()->getIP(),
                                      Network::GetInstance().getHostENR()->getTCPPort(),
                                      Network::GetInstance().getHostENR()->getUDPPort(),
                                      "0x4bbede0846299a5893929f9ebbadcd93933b91c8f4d1f7fe8d7f485c9b168815") )*/
{
    RLPByteStream rlp;
    rlp.push_back(ack_hash);
    rlp.push_back(Network::GetInstance().getHostENR()->getSignedRLP());
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
        m_sender_enr = make_shared<const ENRV4Identity>( ping_msg->getENRSeq(),
                                                         ntohl(ping_msg->getSessionHandler()->getPeerAddress().sin_addr.s_addr),
                                                         ping_msg->getSenderTCPPort(),
                                                         ntohs(ping_msg->getSessionHandler()->getPeerAddress().sin_port),
                                                         ping_msg->getPubKey()
                                                       );
    }
    else if( auto pong_msg = dynamic_pointer_cast<const DiscV4PongMessage>(signed_msg) )
    {
        // DiscV4ENRResponseMessage emulated from DiscV4PongMessage
        m_sender_enr = make_shared<const ENRV4Identity>( pong_msg->getENRSeq(),
                                                         ntohl(pong_msg->getSessionHandler()->getPeerAddress().sin_addr.s_addr),
                                                         0,    // we know nothing about the sender tcp port in the pong msg
                                                         ntohs(pong_msg->getSessionHandler()->getPeerAddress().sin_port),
                                                         pong_msg->getPubKey()
                                                       );
    }
    else
    {
        //True DiscV4ENRResponseMessage
        RLPByteStream msg = RLPByteStream(&(*signed_msg)[0], signed_msg->size());

        //Drops the header:
        // - 32 bytes hash,
        // - 65 bytes signature,
        // - 1 byte type
        msg.ByteStream::pop_front(98);

        m_enr_request_hash = msg.pop_front(is_list);

        auto session = dynamic_pointer_cast<const DiscV4Session>(getSessionHandler());
        if(session)
            m_sender_enr = make_shared<const ENRV4Identity>(getPubKey(), msg.pop_front(is_list));
    }
}

void DiscV4ENRResponseMessage::print() const
{
    auto session =  dynamic_pointer_cast<const DiscV4Session>(getSessionHandler());
    if( session )
    {
        auto server = dynamic_pointer_cast<const DiscV4Server>(session->getSocketHandler());
        if( server )
        {
            cout << dec << "   @UDP DiscV4 ENRRESPONSE:" << endl;
            cout << "   ENR Request hash = 0x" << hex << m_enr_request_hash.as_Integer() << endl;
            if(m_sender_enr)
            {
                cout << "   Peer ENR:" << endl;
                m_sender_enr->print();
            }
            else
            {
                cout << "   Host ENR:" << endl;
                Network::GetInstance().getHostENR()->print();
            }
        }
    }
}
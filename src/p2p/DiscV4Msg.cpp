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
{
    if( hasValidSize() )
    {
        m_hash = ByteStream(&(*this)[0], 32);
        m_hashed_payload = ByteStream(&(*this)[32], size() - 32);
        m_signed_payload = ByteStream(&(*this)[97], size() - 97);
        Signature sig(ByteStream(&(*this)[32], 32).as_Integer(), ByteStream(&(*this)[64], 32).as_Integer(), bool(ByteStream(&(*this)[96], 1)));
        sig.ecrecover(m_pub_key, m_signed_payload.keccak256());
        m_ID = m_pub_key.getKey(Pubkey::Format::XY).keccak256();
        m_type = ByteStream(&(*this)[97], 1).as_uint8();
        m_rlp_payload = ByteStream(&(*this)[98], size() - 98);
    }
}

DiscV4SignedMessage::DiscV4SignedMessage(const shared_ptr<const SessionHandler> session_handler)
    : DiscoveryMessage(session_handler)
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

    resize(signed_msg.byteSize());
    memcpy(this[0], signed_msg, signed_msg.byteSize());
}

//-----------------------------------------------------------------------------------------------------

DiscV4PingMessage::DiscV4PingMessage(const shared_ptr<const SessionHandler> session_handler)
    : DiscV4SignedMessage(session_handler)
    , m_version(4)
    , m_sender_ip(getHostENR()->getIP())
    , m_sender_udp_port(getHostENR()->getUDPPort())
    , m_sender_tcp_port(getHostENR()->getTCPPort())
    , m_recipient_ip(htonl(session_handler->getPeerAddress().sin_addr.s_addr))
    , m_recipient_udp_port(htons(session_handler->getPeerAddress().sin_port)) 
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
    RLPByteStream msg(&(*signed_msg)[0], signed_msg->size());

    //Drops the header:
    // - 32 bytes hash,
    // - 65 bytes signature,
    // - 1 byte type
    msg.ByteStream::pop_front(98);

    m_version = msg.pop_front(is_list).as_uint8();
    RLPByteStream from = msg.pop_front(is_list);
    if( from.byteSize() > 1 )   //non-empty list
    {
        m_sender_ip = from.pop_front(is_list).as_uint64();
        m_sender_udp_port = from.pop_front(is_list).as_uint64(); 
        m_sender_tcp_port = from.pop_front(is_list).as_uint64(); 
    }
    RLPByteStream to = msg.pop_front(is_list);
    if( to.byteSize() > 1 )     //non-empty list
    {
        m_recipient_ip = to.pop_front(is_list).as_uint64();
        m_recipient_udp_port = to.pop_front(is_list).as_uint64(); 
        m_recipient_tcp_port = to.pop_front(is_list).as_uint64(); 
    }
    m_expiration = msg.pop_front(is_list).as_uint64();
    if( msg.byteSize() > 0 )
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
    RLPByteStream msg(&(*signed_msg)[0], signed_msg->size());

    //Drops the header:
    // - 32 bytes hash,
    // - 65 bytes signature,
    // - 1 byte type
    msg.ByteStream::pop_front(98);

    RLPByteStream to = msg.pop_front(is_list);
    if( to.byteSize() > 1 )     //non-empty list
    {
        m_recipient_ip = to.pop_front(is_list).as_uint64();
        m_recipient_udp_port = to.pop_front(is_list).as_uint64();
        m_recipient_tcp_port = to.pop_front(is_list).as_uint64();
    }
    m_ping_hash = msg.pop_front(is_list);
    m_expiration = msg.pop_front(is_list).as_uint64();
    if( msg.byteSize() > 0 )
        m_enr_seq = msg.pop_front(is_list).as_uint64();
}

void DiscV4PongMessage::print() const
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

//-----------------------------------------------------------------------------------------------------

DiscV4FindNodeMessage::DiscV4FindNodeMessage(const shared_ptr<const SessionHandler> session_handler, const Pubkey &target)
    : DiscV4SignedMessage(session_handler)
    , m_target(target)
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
    RLPByteStream msg(&(*signed_msg)[0], signed_msg->size());

    //Drops the header:
    // - 32 bytes hash,
    // - 65 bytes signature,
    // - 1 byte type
    msg.ByteStream::pop_front(98);

    m_target = Pubkey(msg.pop_front(is_list), Pubkey::Format::XY);
    m_expiration = msg.pop_front(is_list).as_uint64();
}

void DiscV4FindNodeMessage::print() const
{
    if( auto server = getConstServer() )
    {
        if( !hasNotExpired() )
            cout << dec << "   @UDP DiscV4 EXPIRED FINDNODE" << endl;
        else
            cout << dec << "   @UDP DiscV4 FINDNODE" << endl;
        cout << "   Target = 0x" << hex << m_target.getKey(Pubkey::Format::XY) << endl;
        cout << "   Expiration = " << dec << m_expiration << ", Now is " << getUnixTimeStamp() << endl;
    }
}

//-----------------------------------------------------------------------------------------------------

DiscV4NeighborsMessage::DiscV4NeighborsMessage(const shared_ptr<const SessionHandler> session_handler, const vector<std::weak_ptr<const ENRV4Identity>> &neighbors_enr)
    : DiscV4SignedMessage(session_handler)
    //, m_nodes(neighbors_enr) FIXME
    , m_expiration(getUnixTimeStamp() + EXPIRATION_DELAY_IN_SEC)
{
    RLPByteStream rlp(ByteStream(), true);
    
    for(auto it = begin(neighbors_enr); it != end(neighbors_enr); it++)
    {
        RLPByteStream node_i;
        if( auto enr = it->lock() )
        {
            node_i.push_back(enr->getIP() ? ByteStream(enr->getIP()) : ByteStream());           //Transmit empty instead of 0
            node_i.push_back(enr->getUDPPort() ? ByteStream(enr->getUDPPort()) : ByteStream()); //Transmit empty instead of 0
            node_i.push_back(enr->getTCPPort() ? ByteStream(enr->getTCPPort()) : ByteStream()); //Transmit empty instead of 0
            node_i.push_back(enr->getPubKey().getKey(Pubkey::Format::XY));
            rlp.push_back(node_i);
        }
    }

    rlp.push_back(ByteStream(m_expiration));
    addTypeSignAndHash(rlp);
    if( rlp.byteSize()+32+65+1 > 1280 )
        cout << hex << rlp.as_Integer() << endl;
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

    RLPByteStream node_list = msg.pop_front(is_list);
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

    m_expiration = msg.pop_front(is_list).as_uint64();
}

void DiscV4NeighborsMessage::print() const
{
    if( auto server = getConstServer() )
    {
        if( !hasNotExpired() )
            cout << dec << "   @UDP DiscV4 EXPIRED NEIGHBORS" << endl;
        else
            cout << dec << "   @UDP DiscV4 NEIGHBORS" << endl;
        auto nodes(m_nodes);
        while( nodes.size() )
        {
            auto node_i = nodes.back();
            cout << "   ----------------------------------------" << endl;
            cout << "   Node IP = " << dec << ((node_i->getIP() >> 24) & 0xFF) << "."
                                            << ((node_i->getIP() >> 16) & 0xFF) << "." 
                                            << ((node_i->getIP() >> 8) & 0xFF) << "." 
                                            << (node_i->getIP() & 0xFF) << endl;
            cout << "   Node UDP PORT = " << dec << node_i->getUDPPort() << endl;
            cout << "   Node TCP PORT = " << dec << node_i->getTCPPort() << endl;
            cout << "   Node PUBLIC KEY = 0x" << hex << node_i->getPubKey().getKey(Pubkey::Format::XY) << endl;

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
    if( auto server = getConstServer() )
    {
        if( !hasNotExpired() )
            cout << dec << "   @UDP DiscV4 EXPIRED ENRREQUEST" << endl;
        else
            cout << dec << "   @UDP DiscV4 ENRREQUEST" << endl;
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
        m_sender_enr = make_shared<const ENRV4Identity>( ping_msg->getENRSeq(),
                                                         ntohl(ping_msg->getSessionHandler()->getPeerAddress().sin_addr.s_addr),
                                                         ntohs(ping_msg->getSessionHandler()->getPeerAddress().sin_port),
                                                         ping_msg->getSenderTCPPort(),
                                                         ping_msg->getPubKey()
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

        m_sender_enr = make_shared<const ENRV4Identity>(msg.pop_front(is_list));
    }
}

void DiscV4ENRResponseMessage::print() const
{
    if( auto server = getConstServer() )
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
            getHostENR()->print();
        }
    }
}
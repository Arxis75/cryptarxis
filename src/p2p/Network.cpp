#include "Network.h"

#include <arpa/inet.h>      // IPPROTO_TCP
#include <iostream>         // cout, EXIT_FAILURE, NULL

using std::cout;
using std::hex;
using std::dec;
using std::endl;
using std::min;

ENRV4Identity::ENRV4Identity(const Pubkey &pub_key, const RLPByteStream &signed_rlp)
    : m_scheme("unknown")
    , m_ip(0)
    , m_tcp_port(0)
    , m_udp_port(0)
    , m_ip6(Integer::zero)
    , m_tcp6_port(0)
    , m_udp6_port(0)
    , m_secret(0)
    , m_pubkey(pub_key)
    , m_ID(m_pubkey.getKey(Pubkey::Format::XY).keccak256())
    , m_signed_rlp(signed_rlp)
{
    bool is_list;
    RLPByteStream tmp = signed_rlp;
    
    // Removes the signature: it is saved in m_signed_rlp though.
    ByteStream field = tmp.pop_front(is_list);

    // Pops the seq counter
    field = tmp.pop_front(is_list);
    assert(field.byteSize() <= 8);      //uint64_t
    m_seq = field.as_uint64();

    //Pops the optional fields
    while( tmp.byteSize() )
    {
        field = tmp.pop_front(is_list);
        if( field == "id" )
        {
            field = tmp.pop_front(is_list);
            assert(field.byteSize() == 2);
            m_scheme = string(field);
        }
        else if( field == "secp256k1" )
        {
            //useless
            field = tmp.pop_front(is_list);
        }
        else if( field == "ip" )
        {
            field = tmp.pop_front(is_list);
            assert(field.byteSize() == 4);
            m_ip = field.as_uint64();
        }
        else if( field == "tcp" )
        {
            field = tmp.pop_front(is_list);
            assert(field.byteSize() == 2);
            m_tcp_port = field.as_uint64();
        }
        else if( field == "udp" )
        {
            field = tmp.pop_front(is_list);
            assert(field.byteSize() == 2);
            m_udp_port = field.as_uint64();
        }
        else if( field == "ip6" )
        {
            field = tmp.pop_front(is_list);
            assert(field.byteSize() == 16);
            m_ip6 = field.as_Integer();
        }
        else if( field == "tcp6" )
        {
            field = tmp.pop_front(is_list);
            assert(field.byteSize() == 2);
            m_tcp6_port = field.as_uint64();
        }
        else if( field == "udp6" )
        {
            field = tmp.pop_front(is_list);
            assert(field.byteSize() == 2);
            m_udp6_port = field.as_uint64();
        }
        else
            // Unhandled field...
            field = tmp.pop_front(is_list);
    }
}

ENRV4Identity::ENRV4Identity(const uint32_t ip, const uint16_t tcp_port, const uint16_t udp_port, const char *secret)
    : m_scheme(ByteStream("v4"))
    , m_ip(ip)
    , m_tcp_port(tcp_port)
    , m_udp_port(udp_port)
    , m_ip6(Integer::zero)
    , m_tcp6_port(0)
    , m_udp6_port(0)
    , m_secret(new Privkey(ByteStream(secret, 32, 16)))
    , m_pubkey(m_secret->getPubKey())
    , m_ID(m_pubkey.getKey(Pubkey::Format::XY).keccak256())
{ 
    //TODO: retrieve it from a config file
    m_seq = 1;

    m_signed_rlp.push_back(ByteStream(m_seq));
    m_signed_rlp.push_back(ByteStream("id"));
    m_signed_rlp.push_back(ByteStream(m_scheme.c_str()));
    m_signed_rlp.push_back(ByteStream("ip"));
    m_signed_rlp.push_back(ByteStream(m_ip));                //assumes 4-bytes ip here (ip cannot start with 0)
    m_signed_rlp.push_back(ByteStream("secp256k1"));
    m_signed_rlp.push_back(m_pubkey.getKey(Pubkey::Format::PREFIXED_X));
    m_signed_rlp.push_back(ByteStream("tcp"));
    m_signed_rlp.push_back(ByteStream(m_tcp_port, 2));
    m_signed_rlp.push_back(ByteStream("udp"));
    m_signed_rlp.push_back(ByteStream(m_udp_port, 2));

    Signature sig = m_secret->sign(m_signed_rlp.keccak256());

    ByteStream signature_field;    
    signature_field.push_front(ByteStream(sig.get_r(), 32));
    signature_field.push_back(ByteStream(sig.get_s(), 32));
    
    m_signed_rlp.push_front(signature_field);
}

ENRV4Identity::~ENRV4Identity()
{
    if(m_secret)
        delete m_secret;
}

const Signature ENRV4Identity::sign(const ByteStream &hash) const
{
    Signature retval(0, 0, 0);
    if(m_secret)
        retval = m_secret->sign(hash);
    return retval;
}

void ENRV4Identity::print() const
{
    cout << "   ENR name = " << getName() << endl;
    cout << "   ENR scheme = " << m_scheme << endl;
    cout << "   ENR public key = 0x" << hex << m_pubkey.getKey(Pubkey::Format::XY).as_Integer() << endl;
    cout << "   ENR ID = 0x" << hex << m_ID << endl;
    cout << "   ENR seq = " << dec << m_seq << endl;
    cout << "   ENR IP = " << dec << ((m_ip >> 24) & 0xFF) << "."
                                  << ((m_ip >> 16) & 0xFF) << "."
                                  << ((m_ip >> 8) & 0xFF) << "."
                                  << (m_ip & 0xFF) << endl;
    cout << "   ENR TCP port = " << dec << m_tcp_port << endl;
    cout << "   ENR UDP port = " << dec << m_udp_port << endl;
    if( m_ip6 != Integer::zero )
    {
        Integer byte_mask = 0xFF;
        cout << "   ENR IP6 = " << dec << ((m_ip6 >> 120) & byte_mask)
                                    << ((m_ip6 >> 112) & byte_mask) << ":"
                                    << ((m_ip6 >> 104) & byte_mask)
                                    << ((m_ip6 >> 96) & byte_mask) << ":"
                                    << ((m_ip6 >> 88) & byte_mask)
                                    << ((m_ip6 >> 80) & byte_mask) << ":"
                                    << ((m_ip6 >> 72) & byte_mask)
                                    << ((m_ip6 >> 64) & byte_mask) << ":"
                                    << ((m_ip6 >> 56) & byte_mask)
                                    << ((m_ip6 >> 48) & byte_mask) << ":"
                                    << ((m_ip6 >> 40) & byte_mask)
                                    << ((m_ip6 >> 32) & byte_mask) << ":"
                                    << ((m_ip6 >> 24) & byte_mask)
                                    << ((m_ip6 >> 16) & byte_mask) << ":"
                                    << ((m_ip6 >> 8) & byte_mask)
                                    << (m_ip6 & byte_mask) << endl;
        cout << "   ENR TCP6 port = " << dec << m_tcp6_port << endl;
        cout << "   ENR UDP6 port = " << dec << m_udp6_port << endl;
    }
}

//-------------------------------------------------------------------------------------------------------------------------

Network& Network::GetInstance()
{
    if (m_sInstancePtr == NULL)
        m_sInstancePtr = new Network();

    return *m_sInstancePtr;
}

void Network::start(const uint32_t ip, const uint16_t udp_port, const uint16_t tcp_port, const char *secret, const uint64_t seq)
{
    m_host_enr = new ENRV4Identity(ip, tcp_port, udp_port, secret);

    m_udp_server = make_shared<DiscV4Server>(m_host_enr->getUDPPort(), IPPROTO_UDP);
    if( m_udp_server )
    {
        m_udp_server->start();

        //m_tcp_tcp = make_shared<Eth67Server>(m_host_enr->getTCPPort(), IPPROTO_TCP);
        //if( m_tcp_server )
        //{
        //    m_tcp_server->start();

            // Main event loop that handles client
            // logging records and connection requests.
            while(true)
                Initiation_Dispatcher::GetInstance().handle_events();
        //}
    }
}

void Network::onNewNodeCandidates(const RLPByteStream &node_list)
{
    bool is_list;
    RLPByteStream nodes(node_list);
    while( nodes.byteSize() > 1 )
    {
        RLPByteStream node_i = nodes.pop_front(is_list);
        uint32_t node_ip = node_i.pop_front(is_list).as_uint64();
        uint16_t node_udp_port = node_i.pop_front(is_list).as_uint64();
        uint16_t node_tcp_port = node_i.pop_front(is_list).as_uint64();
        ByteStream node_pub_key = node_i.pop_front(is_list);
        
        // Is it a real peer and not me?
        // Does this peer need a ping?
        if( node_ip != getHostENR()->getIP() )
        {
            //Get the master UDP socket
            if(m_udp_server)
            {
                struct sockaddr_in peer_address;
                peer_address.sin_family = AF_INET;
                peer_address.sin_addr.s_addr = htonl(node_ip);
                peer_address.sin_port = htons(node_udp_port); 
                
                Pubkey pub_key(node_pub_key, Pubkey::Format::XY);

                //Is there already a existing session (IP/Port) for this peer?
                auto session = dynamic_pointer_cast<const DiscV4Session>(m_udp_server->getSessionHandler(peer_address));
                if(!session)
                {
                    //Creates a new session for this new peer
                    session = dynamic_pointer_cast<const DiscV4Session>(m_udp_server->registerSessionHandler(peer_address));
                    //Sets the pubkey according to what was advertised
                    const_pointer_cast<DiscV4Session>(session)->initPublicKey(pub_key);
                }
                
                //Has this peer recently responded to a ping?
                if( !session->isVerified() )
                    // Pings the peer
                    const_pointer_cast<DiscV4Session>(session)->sendPing();
            }
        }
    }
}

Network *Network::m_sInstancePtr = NULL;
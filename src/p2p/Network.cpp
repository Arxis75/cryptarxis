#include "Network.h"

#include <arpa/inet.h>      // IPPROTO_TCP
#include <iostream>         // cout, EXIT_FAILURE, NULL

using std::cout;
using std::hex;
using std::dec;
using std::endl;
using std::min;

ENRV4Identity::ENRV4Identity(const ENRV4Identity& id)
    : m_timestamp(id.m_timestamp)
    , m_seq(id.m_seq)
    , m_scheme(id.m_scheme)
    , m_ip(id.m_ip)
    , m_tcp_port(id.m_tcp_port)
    , m_udp_port(id.m_udp_port)
    , m_ip6(id.m_ip6)
    , m_tcp6_port(id.m_tcp6_port)
    , m_udp6_port(id.m_udp6_port)
    , m_secret(id.m_secret)
    , m_pubkey(id.m_pubkey)
    , m_ID(id.m_ID)
    , m_unsigned_rlp(id.m_unsigned_rlp)
    , m_signed_rlp(id.m_signed_rlp)
    , m_is_signed(id.m_is_signed)
{ }

ENRV4Identity::ENRV4Identity(const Pubkey &pub_key, const RLPByteStream &signed_rlp)
    : m_timestamp(getUnixTimeStamp())
    , m_scheme("unknown")
    , m_ip(0)
    , m_tcp_port(0)
    , m_udp_port(0)
    , m_ip6(Integer::zero)
    , m_tcp6_port(0)
    , m_udp6_port(0)
    , m_secret(shared_ptr<const Privkey>(nullptr))
    , m_pubkey(pub_key)
    , m_ID(m_pubkey.getKey(Pubkey::Format::XY).keccak256())
    , m_is_signed(true)
    , m_signed_rlp(signed_rlp)
{
    bool is_list;
    RLPByteStream tmp = signed_rlp;
    
    // Removes the signature: it is saved in m_signed_rlp though.
    ByteStream field = tmp.pop_front(is_list);

    m_unsigned_rlp = tmp;

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

ENRV4Identity::ENRV4Identity(const uint32_t ip, const uint16_t udp_port, const uint16_t tcp_port, const char *secret)
    : m_timestamp(getUnixTimeStamp())
    , m_scheme(ByteStream("v4"))
    , m_ip(ip)
    , m_udp_port(udp_port)
    , m_tcp_port(tcp_port)
    , m_ip6(Integer::zero)
    , m_udp6_port(0)
    , m_tcp6_port(0)
    , m_secret(make_shared<const Privkey>(ByteStream(secret, 32, 16)))
    , m_pubkey(m_secret->getPubKey())
    , m_ID(m_pubkey.getKey(Pubkey::Format::XY).keccak256())
    , m_is_signed(true)
{ 
    //TODO: retrieve it from a config file
    m_seq = 1;

    m_unsigned_rlp.push_back(ByteStream(m_seq));
    m_unsigned_rlp.push_back(ByteStream("id"));
    m_unsigned_rlp.push_back(ByteStream(m_scheme.c_str()));
    m_unsigned_rlp.push_back(ByteStream("ip"));
    m_unsigned_rlp.push_back(ByteStream(m_ip));                //assumes 4-bytes ip here (ip cannot start with 0)
    m_unsigned_rlp.push_back(ByteStream("secp256k1"));
    m_unsigned_rlp.push_back(m_pubkey.getKey(Pubkey::Format::PREFIXED_X));
    m_unsigned_rlp.push_back(ByteStream("udp"));
    m_unsigned_rlp.push_back(ByteStream(m_udp_port, 2));
    m_unsigned_rlp.push_back(ByteStream("tcp"));
    m_unsigned_rlp.push_back(ByteStream(m_tcp_port, 2));

    Signature sig = m_secret->sign(m_unsigned_rlp.keccak256());

    ByteStream signature_field;    
    signature_field.push_front(ByteStream(sig.get_r(), 32));
    signature_field.push_back(ByteStream(sig.get_s(), 32));
    
    m_signed_rlp = m_unsigned_rlp;
    m_signed_rlp.push_front(signature_field);
}

ENRV4Identity::ENRV4Identity(const uint64_t seq, const uint32_t ip, const uint16_t udp_port, const uint16_t tcp_port, const Pubkey &pub_key)
    : m_timestamp(getUnixTimeStamp())
    , m_seq(seq)
    , m_scheme(ByteStream("v4"))
    , m_ip(ip)
    , m_udp_port(udp_port)
    , m_tcp_port(tcp_port)
    , m_ip6(Integer::zero)
    , m_udp6_port(0)
    , m_tcp6_port(0)
    , m_secret(0)
    , m_pubkey(pub_key)
    , m_ID(m_pubkey.getKey(Pubkey::Format::XY).keccak256())
    , m_is_signed(false)
{ }

bool ENRV4Identity::equals(const shared_ptr<const ENRV4Identity> enr) const
{
    return  //m_seq == enr->m_seq &&
            m_ip == enr->m_ip &&
            m_tcp_port == enr->m_tcp_port &&
            m_udp_port == enr->m_udp_port &&
            m_pubkey == enr->m_pubkey;          //implicitely compares the private keys
}

const Signature ENRV4Identity::sign(const ByteStream &hash) const
{
    Signature retval(0, 0, 0);
    if(m_secret)
        retval = m_secret->sign(hash);
    return retval;
}

bool ENRV4Identity::hasValidSignature() const
{
    bool retval = false;
    if( m_signed_rlp.byteSize() >= 64 )
    {
        bool is_list;
        Pubkey key_0, key_1;

        // Retrieves the incomplete Signature
        // of the ENR record (64 bytes only)
        RLPByteStream tmp = m_signed_rlp;
        ByteStream incomp_sig = tmp.pop_front(is_list);

        //Builds 2 complete candidate signatures
        Signature sig_0(ByteStream(&(incomp_sig)[0], 32).as_Integer(), ByteStream(&(incomp_sig)[32], 32).as_Integer(), false);
        Signature sig_1(ByteStream(&(incomp_sig)[0], 32).as_Integer(), ByteStream(&(incomp_sig)[32], 32).as_Integer(), true);

        sig_0.ecrecover(key_0, m_unsigned_rlp.keccak256());
        sig_1.ecrecover(key_1, m_unsigned_rlp.keccak256());

        // Verifies that the pubkey who built the ENR is
        // matching one of the ENR signature ecrecover candidates
        retval = (m_pubkey == key_0 || m_pubkey == key_1);
    }
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

Network::Network()
    : m_host_enr(shared_ptr<const ENRV4Identity>(nullptr))
    , m_udp_server(shared_ptr<DiscV4Server>(nullptr))
{ }


Network& Network::GetInstance()
{
    if (m_sInstancePtr == NULL)
        m_sInstancePtr = new Network();

    return *m_sInstancePtr;
}

void Network::start(const uint32_t ip, const uint16_t udp_port, const uint16_t tcp_port, const char *secret, const uint64_t seq)
{
    m_host_enr = make_shared<const ENRV4Identity>(ip, udp_port, tcp_port, secret);

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
void Network::onNewNodeCandidates(const vector<std::shared_ptr<const ENRV4Identity>> &node_list) const
{
    for(auto it = begin(node_list);it!=end(node_list);it++)
    {
        if( auto node_i = *it )
        {
            // Is it a real peer (not 0.0.0.0:0000) and not me?
            if( (node_i->getIP() && node_i->getUDPPort()) &&
                node_i->getIP() != getHostENR()->getIP() &&
                node_i->getUDPPort() != getHostENR()->getUDPPort() &&
                node_i->getPubKey() != getHostENR()->getPubKey() )
            {
                //Get the master UDP socket
                if(m_udp_server)
                {
                    struct sockaddr_in peer_address;
                    peer_address.sin_family = AF_INET;
                    peer_address.sin_addr.s_addr = htonl(node_i->getIP());
                    peer_address.sin_port = htons(node_i->getUDPPort()); 

                    if( !m_udp_server->isBlacklisted(peer_address) )
                    {
                        auto session = dynamic_pointer_cast<const DiscV4Session>(m_udp_server->getSessionHandler(peer_address));
                        if(!session)
                        {
                            // Creates a new session
                            session = dynamic_pointer_cast<const DiscV4Session>(m_udp_server->registerSessionHandler(peer_address));

                            // Pings the peer
                            const_pointer_cast<DiscV4Session>(session)->sendPing();
                        }
                    }
                }
            }
        }
    }
}

bool Network::handleRoaming(const Pubkey &pub_key, const shared_ptr<const DiscV4Session> session) const
{
    bool roaming = false;
    auto roaming_session = findSessionByID(pub_key);
    if( roaming_session && roaming_session != session )
    {
        //We have a previous session with different IP/Port
        //but same nodeID => this is Peer roaming, close the previous session
        const_pointer_cast<DiscV4Session>(roaming_session)->close();
        roaming = true;
    }
    return roaming;
}

const shared_ptr<const DiscV4Session> Network::findSessionByID(const Pubkey &node_pub_key) const
{
    auto it = m_enr_session_list.find(node_pub_key.getKey(Pubkey::Format::XY));
    if( it != std::end(m_enr_session_list) ) 
    {
        auto weak_ptr = it->second;
        if( auto session = weak_ptr.lock() )
            return session;
    }
    return shared_ptr<const DiscV4Session>(nullptr); 
}

const shared_ptr<const DiscV4Session> Network::findSessionByAddress(const struct sockaddr_in &node_address) const
{
    return std::dynamic_pointer_cast<const DiscV4Session>(m_udp_server->getSessionHandler(node_address));
}

void Network::registerENRSession(const shared_ptr<const DiscV4Session> session)
{
    if( session && session->getENR() )
    {
        //Insert the session indexed by its Public key
        m_enr_session_list.insert(make_pair(session->getENR()->getPubKey().getKey(Pubkey::Format::XY), session)); 
        cout << "--------------------------------------------------------------- registerENRSession ENR SESSION COUNT = " << dec << m_enr_session_list.size() << endl;  
    }
}

void Network::removeENRSession(const Pubkey &pub_key)
{
    //removes from the ENR session list
    m_enr_session_list.erase(pub_key.getKey(Pubkey::Format::XY));
    cout << "--------------------------------------------------------------- removeENRSession ENR SESSION COUNT = " << dec << m_enr_session_list.size() << endl;  
}

vector<std::weak_ptr<const ENRV4Identity>> Network::findNeighbors(const Pubkey &target) const
{
    vector<std::weak_ptr<const ENRV4Identity>> neighbors_vector;

    map<Integer, std::weak_ptr<const ENRV4Identity>> neighbors_map;
    auto it1 = begin(m_enr_session_list);
    while( it1!= end(m_enr_session_list) )
    {
        if(auto session = it1->second.lock() )
        {
            Integer distance = it1->first.keccak256().as_Integer() ^ target.getKey(Pubkey::Format::XY).keccak256().as_Integer();
            neighbors_map.insert(std::make_pair(distance, session->getENR()));
        }
        it1++;
    }

    auto it2 = begin(neighbors_map);
    while( it2!= end(neighbors_map) && neighbors_vector.size() < 16 ) 
    {
        if(auto enr = it2->second.lock() )
        {
            //cout << dec << it2->first << endl;
            neighbors_vector.push_back(enr);
        }
        it2++;
    }
    return neighbors_vector;
}

Network *Network::m_sInstancePtr = NULL;
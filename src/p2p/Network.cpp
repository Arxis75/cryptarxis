#include "Network.h"
#include "DiscV4.h"
#include "DiscV5.h"

#include <arpa/inet.h>      // IPPROTO_TCP
#include <iostream>         // cout, EXIT_FAILURE, NULL

using std::cout;
using std::hex;
using std::dec;
using std::endl;
using std::min;

//Copy constructor
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

//ENRRESPONSE message
ENRV4Identity::ENRV4Identity(const RLPByteStream &signed_rlp)
    : m_timestamp(getUnixTimeStamp())
    , m_signed_rlp(signed_rlp)
    , m_is_signed(true)
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
            //assert(field.byteSize() == 2);
            m_scheme = string(field);
        }
        else if( field == "secp256k1" )
        {
            field = tmp.pop_front(is_list);
            assert(field.byteSize() == 33);
            m_pubkey = Pubkey(field, Pubkey::Format::PREFIXED_X);
            m_ID = ByteStream(m_pubkey.getID());
        }
        else if( field == "ip" )
        {
            field = tmp.pop_front(is_list);
            //assert(field.byteSize() == 4);
            m_ip = field.as_uint64();
        }
        else if( field == "tcp" )
        {
            field = tmp.pop_front(is_list);
            //assert(field.byteSize() == 2);
            m_tcp_port = field.as_uint64();
        }
        else if( field == "udp" )
        {
            field = tmp.pop_front(is_list);
            //assert(field.byteSize() == 2);
            m_udp_port = field.as_uint64();
        }
        else if( field == "ip6" )
        {
            field = tmp.pop_front(is_list);
            //assert(field.byteSize() == 16);
            m_ip6 = field.as_Integer();
        }
        else if( field == "tcp6" )
        {
            field = tmp.pop_front(is_list);
            //assert(field.byteSize() == 2);
            m_tcp6_port = field.as_uint64();
        }
        else if( field == "udp6" )
        {
            field = tmp.pop_front(is_list);
            //assert(field.byteSize() == 2);
            m_udp6_port = field.as_uint64();
        }
        else
            // Unhandled field...
            field = tmp.pop_front(is_list);
    }
}

//HOST ENR Identity
ENRV4Identity::ENRV4Identity(const uint64_t seq, const uint32_t ip, const uint16_t udp_port, const uint16_t tcp_port, const char *secret)
    : m_timestamp(getUnixTimeStamp())
    , m_seq(seq)
    , m_scheme(ByteStream("v4"))
    , m_ip(ip)
    , m_udp_port(udp_port)
    , m_tcp_port(tcp_port)
    , m_secret(make_shared<const Privkey>(ByteStream(secret, 32, 16)))
    , m_pubkey(m_secret->getPubKey())
    , m_ID(m_pubkey.getID())
    , m_is_signed(true)
{ 
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

//Pseudo-ENR built from a DiscV4 PING message: no m_signed_rlp
ENRV4Identity::ENRV4Identity(const uint64_t seq, const uint32_t ip, const uint16_t udp_port, const uint16_t tcp_port, const Pubkey &pub_key)
    : m_timestamp(getUnixTimeStamp())
    , m_seq(seq)
    , m_ip(ip)
    , m_udp_port(udp_port)
    , m_tcp_port(tcp_port)
    , m_pubkey(pub_key)
    , m_ID(m_pubkey.getID())
    , m_is_signed(false)
{ 
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
}

const sockaddr_in ENRV4Identity::getUDPAddress() const
{
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(getIP());
    address.sin_port = htons(getUDPPort());
    return address;
}

const sockaddr_in ENRV4Identity::getTCPAddress() const
{
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(getIP());
    address.sin_port = htons(getTCPPort());
    return address;
}

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
    if( isSigned() )
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
    cout << "      ENR name = " << getName() << endl;
    cout << "      ENR scheme = " << m_scheme << endl;
    cout << "      ENR public key = 0x" << hex << m_pubkey.getKey(Pubkey::Format::XY).as_Integer() << endl;
    cout << "      ENR ID = 0x" << hex << m_ID << endl;
    cout << "      ENR seq = " << dec << m_seq << endl;
    cout << "      ENR IP = " << dec << ((m_ip >> 24) & 0xFF) << "."
                                     << ((m_ip >> 16) & 0xFF) << "."
                                     << ((m_ip >> 8) & 0xFF) << "."
                                     << (m_ip & 0xFF) << endl;
    cout << "      ENR TCP port = " << dec << m_tcp_port << endl;
    cout << "      ENR UDP port = " << dec << m_udp_port << endl;
    if( m_ip6 != Integer::zero )
    {
        Integer byte_mask = 0xFF;
        cout << "      ENR IP6 = " << dec << ((m_ip6 >> 120) & byte_mask)
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
        cout << "      ENR TCP6 port = " << dec << m_tcp6_port << endl;
        cout << "      ENR UDP6 port = " << dec << m_udp6_port << endl;
    }
}

//-------------------------------------------------------------------------------------------------------------------------

Network::Network()
    : m_host_enr(shared_ptr<const ENRV4Identity>(nullptr))
    , m_udp_server(shared_ptr<DiscoveryServer>(nullptr))
    //, m_tcp_server(shared_ptr<DiscoveryServer>(nullptr))
{ }


Network& Network::GetInstance()
{
    if (m_sInstancePtr == NULL)
        m_sInstancePtr = new Network();

    return *m_sInstancePtr;
}

void Network::start( const uint32_t ip, const uint16_t udp_port, const uint16_t tcp_port, const char *secret, 
                     const string &udp_protocol, const string &tcp_protocol, const uint64_t seq )
{
    m_host_enr = make_shared<const ENRV4Identity>(seq, ip, udp_port, tcp_port, secret);

    if(udp_protocol == "discv4")
        m_udp_server = make_shared<DiscV4Server>(m_host_enr);
    else if(udp_protocol == "discv5")
        m_udp_server = make_shared<DiscV5Server>(m_host_enr);

    if( m_udp_server )
    {
        m_udp_server->start();

        //m_tcp_tcp = make_shared<Eth67Server>(m_host_enr->getTCPPort());
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

Network *Network::m_sInstancePtr = NULL;
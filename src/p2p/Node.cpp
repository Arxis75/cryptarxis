#include "Node.h"

#include <Common.h>
#include <crypto/bips.h>
#include <iostream>         //cout, EXIT_FAILURE, NULL

using std::cout;
using std::hex;
using std::dec;
using std::endl;
using std::min;

ENRV4Identity::ENRV4Identity(const uint32_t ip, const uint16_t port, const int protocol)
    : m_seq(0)
    , m_scheme("unknown")
    , m_ip(ip)
    , m_tcp_port(0)
    , m_udp_port(0)
    , m_secret(0)
    , m_pubkey(Point())
    , m_ID(Integer::zero)
    , m_signed_rlp(RLPByteStream())
{
    if(protocol == IPPROTO_TCP)
       m_tcp_port = port;
    else if(protocol == IPPROTO_UDP)
        m_udp_port = port;
}

ENRV4Identity::ENRV4Identity(const RLPByteStream &signed_rlp)
    : m_scheme("unknown")
    , m_ip(0)
    , m_tcp_port(0)
    , m_udp_port(0)
    , m_secret(0)
    , m_pubkey(Point())
    , m_ID(Integer::zero)
    , m_signed_rlp(signed_rlp)
{
    bool is_list;
    RLPByteStream tmp = m_signed_rlp;
    
    //Removes the signature
    ByteStream field = tmp.pop_front(is_list);
    assert(field.byteSize() == 64);
    m_r = field.pop_front(32);
    m_s = field.pop_front(32);

    //We get the unsigned RLP
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
        else
            field = tmp.pop_front(is_list);
    }
    
    // Builds the name upon the signed record
    m_name = base64_url_encode(m_signed_rlp);
}

ENRV4Identity::ENRV4Identity(const uint32_t ip, const uint16_t tcp_port, const uint16_t udp_port, const char *secret, const uint64_t seq )
    : m_seq(seq)
    , m_scheme(ByteStream("v4"))
    , m_ip(ip)
    , m_tcp_port(tcp_port)
    , m_udp_port(udp_port)
{
    m_secret = new Privkey(ByteStream(secret, 32, 16));
    m_pubkey = m_secret->getPubKey();

    m_unsigned_rlp.push_back(ByteStream(m_seq));
    m_unsigned_rlp.push_back(ByteStream("id"));
    m_unsigned_rlp.push_back(ByteStream(m_scheme.c_str()));
    m_unsigned_rlp.push_back(ByteStream("ip"));
    m_unsigned_rlp.push_back(ByteStream(m_ip));        //assumes 4-bytes ip here (ip cannot start with 0)
    m_unsigned_rlp.push_back(ByteStream("secp256k1"));
    m_unsigned_rlp.push_back(m_secret->getPubKey().getKey(Pubkey::Format::PREFIXED_X));
    m_unsigned_rlp.push_back(ByteStream("udp"));
    m_unsigned_rlp.push_back(ByteStream(m_udp_port, 2));
    
    Signature sig = m_secret->sign(m_unsigned_rlp.keccak256());
    m_r = sig.get_r();
    m_s = sig.get_s();
    
    ByteStream signature_field;
    signature_field.push_front(ByteStream(m_r, 32));
    signature_field.push_back(ByteStream(m_s, 32));

    m_signed_rlp = m_unsigned_rlp;
    m_signed_rlp.push_front(signature_field);

    // Builds the ID upon the public key
    m_ID = m_secret->getPubKey().getKey(Pubkey::Format::XY).keccak256();

    // Builds the name upon the signed record
    m_name = base64_url_encode(m_signed_rlp);
}

ENRV4Identity::~ENRV4Identity()
{
    if(m_secret)
        delete m_secret;
}

bool ENRV4Identity::validatePubKey(const Pubkey &key)
{
    bool retval = false;
    Pubkey key_candidate1, key_candidate2;
    Signature sig_candidate1(m_r, m_s, 0);
    Signature sig_candidate2(m_r, m_s, 1);

    if( sig_candidate1.ecrecover(key_candidate1, m_unsigned_rlp.keccak256()) && key_candidate1 == key )
    {
        m_pubkey = key_candidate1;
        m_ID = m_pubkey.getKey(Pubkey::Format::XY).keccak256();
        retval = true;
    }
    else if(sig_candidate2.ecrecover(key_candidate2, m_unsigned_rlp.keccak256()) && key_candidate2 == key )
    {
        m_pubkey = key_candidate2;
        m_ID = m_pubkey.getKey(Pubkey::Format::XY).keccak256();
        retval = true;
    }
    return retval;
}

const Signature ENRV4Identity::sign(const ByteStream &hash) const
{
    Signature retval(0, 0, 0);
    if(m_secret)
        retval = m_secret->sign(hash);
    return retval;
}

//---------------------------------------------------------------------------------------------------------------------------

/*EthNode::EthNode(ENRV4Identity *enr)
{
    m_sEnr = enr;
}

void EthNode::startServer(const int master_protocol)
{
    uint16_t master_port = (master_protocol == IPPROTO_TCP ? m_sEnr->getTCPPort() :  m_sEnr->getUDPPort());
    if( shared_ptr<EthSessionManager> server = make_shared<EthSessionManager>(master_port, master_protocol) )
        server->start();
}

EthNode &EthNode::GetInstance(ENRV4Identity *enr)
{
    if (m_sInstancePtr == NULL)
    {
        m_sInstancePtr = new EthNode(enr);
    }

    return *m_sInstancePtr;
}

EthNode *EthNode::m_sInstancePtr = NULL;
ENRV4Identity* EthNode::m_sEnr = NULL;*/
#include "DiscV5Msg.h"
#include "DiscV5.h"
#include "Network.h"

#include <crypto/AES.h>
#include <arpa/inet.h>

#include <openssl/rand.h>   //RAND_bytes

#include <iostream>         //cout

using std::cout;
using std::hex;
using std::dec;
using std::endl;
using std::dynamic_pointer_cast;

#define EXPIRATION_DELAY_IN_SEC 20

DiscV5UnauthMessage::DiscV5UnauthMessage(const shared_ptr<const DiscV5UnauthMessage> unauth_msg)
    : DiscoveryMessage(unauth_msg)
    , m_masking_iv(unauth_msg->m_masking_iv)
    , m_masked_header(unauth_msg->m_masked_header)
    , m_protocol_id(unauth_msg->m_protocol_id)
    , m_version(unauth_msg->m_version)
    , m_flag(unauth_msg->m_flag)
    , m_nonce(unauth_msg->m_nonce)
    , m_authdata_size(unauth_msg->m_authdata_size)
    , m_authdata(unauth_msg->m_authdata)
    , m_message_data(unauth_msg->m_message_data)
{ 
    //TODO: Are the session variables copied as well? (challenge_data, session_key, etc...)
}

DiscV5UnauthMessage::DiscV5UnauthMessage(const shared_ptr<const SocketHandler> handler, const vector<uint8_t> buffer, const struct sockaddr_in &peer_addr, const bool is_ingress)
    : DiscoveryMessage(handler, buffer, peer_addr, is_ingress)
{   
    if( size() > 24 )
    {
        m_masking_iv = ByteStream(&buffer[0], 16);
        ByteStream masked_remainder(&buffer[16], size() - 16);

        ByteStream masking_key(&getHostENR()->getID()[0], 16);

        ByteStream unmasked_remainder;
        unmasked_remainder.resize(masked_remainder.byteSize());

        ctr_decrypt( masked_remainder, masked_remainder.byteSize(),
                     masking_key,
                     m_masking_iv, m_masking_iv.byteSize(),
                     unmasked_remainder );

        m_protocol_id = ByteStream(&unmasked_remainder[0], 6);
        m_version = ByteStream(&unmasked_remainder[6], 2).as_uint64();
        m_flag = (Flag)ByteStream(&unmasked_remainder[8], 1).as_uint8();
        m_nonce = ByteStream(&unmasked_remainder[9], 12);
        m_authdata_size = ByteStream(&unmasked_remainder[21], 2).as_uint64();
        m_authdata = ByteStream(&unmasked_remainder[23], m_authdata_size);

        m_masked_header = masked_remainder.pop_front(23 + m_authdata_size);

        if( size() > 39 + m_authdata_size )
            m_message_data = ByteStream(&buffer[39 + m_authdata_size], size() - (39 + m_authdata_size) );
    }
}

DiscV5UnauthMessage::DiscV5UnauthMessage(const shared_ptr<const SessionHandler> session_handler)
    : DiscoveryMessage(session_handler)
    , m_flag(Flag::UKNOWN)
    , m_authdata_size(0)
{
    m_masking_iv = ByteStream::generateRandom(16);
    m_protocol_id = ByteStream("discv5");
    m_version = 0x0001;
}

const ByteStream DiscV5UnauthMessage::getHeader() const
{
    ByteStream header;
    header.push_back(m_protocol_id);
    header.push_back(ByteStream(Integer(m_version), 2));
    header.push_back((uint8_t)m_flag);
    header.push_back(m_nonce);       
    header.push_back(ByteStream(Integer(m_authdata_size), 2));
    header.push_back(m_authdata);
    return header;
}

void DiscV5UnauthMessage::encryptMessage()
{
    //Fills the final DiscV5 encrypted message content
    clear();
    
    push_back(getMaskingIV());

    if( auto session = dynamic_pointer_cast<const DiscV5Session>(getSessionHandler()) )
    {
        ByteStream header = getHeader();
        ByteStream masking_key(&session->getENR()->getID()[0], 16);

        m_masked_header.clear();
        m_masked_header.resize(header.byteSize());

        ctr_encrypt( header, header.byteSize(),
                     masking_key,
                     getMaskingIV(), getMaskingIV().byteSize(),
                     m_masked_header );
    }

    push_back(getMaskedHeader());

    if( getMessageData().byteSize() )
        push_back(getMessageData());
}

const string DiscV5UnauthMessage::getName() const
{
    switch( getFlag() )
    {
    case Flag::ORDINARY :
        return "ORDINARY";
    case Flag::WHOAREYOU :
        return "WHOAREYOU";
    case Flag::HANDSHAKE :
        return "HANDSHAKE";
    default:
        return "UNKNOWN";
    }
}

void DiscV5UnauthMessage::print() const
{
    DiscoveryMessage::print();

    cout << "  @UDP DiscV4 " << getName() << " MESSAGE:" <<endl;
    SocketMessage::print();   // Printing raw byteStream
    cout << "    Size : " << dec << size() << endl;
    cout << "    Masking IV : 0x" << hex << getMaskingIV() << endl;
    cout << "    Protocol-id : " << string(getProtocol()) << endl;
    cout << "    Version : " << dec << getVersion() << endl;
    cout << "    Nonce : 0x" << hex << getNonce() << endl;
    cout << "    AuthData-size : " << dec << getAuthDataSize() << endl;
}

//-----------------------------------------------------------------------------------------------------

//Copy Constructor
DiscV5WhoAreYouMessage::DiscV5WhoAreYouMessage(const shared_ptr<const DiscV5WhoAreYouMessage> way_msg)
    : DiscV5UnauthMessage(way_msg)
    , m_id_nonce(way_msg->m_id_nonce)
    , m_enr_seq(way_msg->m_enr_seq)
{ }

//Parsing Constructor
DiscV5WhoAreYouMessage::DiscV5WhoAreYouMessage(const shared_ptr<const DiscV5UnauthMessage> unauth_msg)
    : DiscV5UnauthMessage(unauth_msg)
{
    m_id_nonce = ByteStream(&getAuthData()[0], 16);                
    m_enr_seq = ByteStream(&getAuthData()[16], 8).as_uint64();    
}

//session-embedded empty msg
DiscV5WhoAreYouMessage::DiscV5WhoAreYouMessage(const shared_ptr<const SessionHandler> session_handler, const ByteStream &request_nonce)
    : DiscV5UnauthMessage(session_handler)
{
    if( auto session = dynamic_pointer_cast<const DiscV5Session>(getSessionHandler()) )
    {
        m_flag = Flag::WHOAREYOU;
        m_nonce = request_nonce;
        m_authdata_size = 24;
        
        m_id_nonce = ByteStream::generateRandom(16);
        m_enr_seq = (session->getENR() ? session->getENR()->getSeq() : 0);

        encryptMessage();
    }
}

void DiscV5WhoAreYouMessage::encryptMessage()
{
    m_authdata.clear();
    m_authdata.push_back(m_id_nonce);
    m_authdata.push_back(m_enr_seq, 8);
    
    DiscV5UnauthMessage::encryptMessage();
}

const ByteStream DiscV5WhoAreYouMessage::getChallengeData() const
{
    ByteStream retval = getMaskingIV();
    retval.push_back(getHeader());
    return retval;
}

void DiscV5WhoAreYouMessage::print() const
{
    DiscV5UnauthMessage::print();

    cout << "    Challenge-data : 0x" << hex << getChallengeData() << endl;
    cout << "    ID-Nonce : 0x" << hex << getIDNonce() << endl;
    cout << "    ENR-Seq : " << dec << getENRSeq() << endl;
    cout << "-----------------------------------------------------------------------------------" << endl;
}

//-----------------------------------------------------------------------------------------------------

//Copy Constructor
DiscV5AuthMessage::DiscV5AuthMessage(const shared_ptr<const DiscV5AuthMessage> auth_msg, bool add_hanshake_header)
    : DiscV5UnauthMessage(auth_msg)
    , m_src_ID(auth_msg->m_src_ID)
    , m_id_sig_size(auth_msg->m_id_sig_size)
    , m_eph_pub_key_size(auth_msg->m_eph_pub_key_size)
    , m_id_sig(auth_msg->m_id_sig)
    , m_eph_pub_key(auth_msg->m_eph_pub_key)
    , m_enr(auth_msg->m_enr)
    , m_type(auth_msg->m_type)
    , m_rlp_payload(auth_msg->m_rlp_payload)
{
    if(getFlag() == Flag::ORDINARY && add_hanshake_header)
    {
        addHandshakeHeader();
        encryptMessage();
    }
}

//Parsing Constructor
DiscV5AuthMessage::DiscV5AuthMessage(const shared_ptr<const DiscV5UnauthMessage> unauth_msg)
    : DiscV5UnauthMessage(unauth_msg)
    , m_id_sig_size(0)
    , m_eph_pub_key_size(0)
    , m_enr(shared_ptr<const ENRV4Identity>(nullptr))
{
    if( auto session  = dynamic_pointer_cast<const DiscV5Session>(getSessionHandler()) )
    {
        //FIXME: we keep 0 as peer_id 
        //m_peer_ID = ByteStream(&getHeader()[23], 32);
        m_src_ID = ByteStream(&getAuthData()[0], 32);
        
        if( getFlag() == Flag::HANDSHAKE )
        {
            m_id_sig_size = getAuthData()[32];
            m_eph_pub_key_size = getAuthData()[33];
            // id_signature = r || s
            m_id_sig = ByteStream(&getAuthData()[34], getIDSignatureSize());    
            // eph_pubkey = x || y
            m_eph_pub_key = Pubkey(ByteStream(&getAuthData()[34 + getIDSignatureSize()], getEphemeralPubKeySize()), Pubkey::Format::PREFIXED_X);   

            extractHandshakeKeys();

            int enr_ofs = 34 + getIDSignatureSize() + getEphemeralPubKeySize();
            int enr_size = getAuthDataSize() - enr_ofs;
            if( enr_size )
                m_enr = make_shared<const ENRV4Identity>(RLPByteStream(&getAuthData()[enr_ofs], enr_size));
        }

        ByteStream aad;
        aad.push_back(getMaskingIV());
        aad.push_back(getHeader());

        //There is a 16-bytes Tag that is postfixed to the ciphertext
        ByteStream ciphertext(&getMessageData()[0], getMessageData().byteSize() - 16);
        ByteStream tag(&getMessageData()[getMessageData().byteSize() - 16], 16);
        //---------------------FIXME

        ByteStream pt = ByteStream(Integer::zero, ciphertext.byteSize());

        gcm_decrypt(ciphertext, ciphertext.byteSize(),
                    aad, aad.byteSize(),
                    tag,
                    session->getPeerSessionKey(),
                    getNonce(), getNonce().byteSize(),
                    pt);
        
        m_type = pt.pop_front(1).as_uint8();
        m_rlp_payload = RLPByteStream(&pt[0], pt.byteSize());
    }
}

//session-embedded empty msg
DiscV5AuthMessage::DiscV5AuthMessage(const shared_ptr<const SessionHandler> session_handler, const bool with_handshake, const uint8_t type)
    : DiscV5UnauthMessage(session_handler)
    , m_type(type)
{
    if( auto session = const_pointer_cast<DiscV5Session>(dynamic_pointer_cast<const DiscV5Session>(session_handler)) )
    {
        m_flag = (with_handshake ? Flag::HANDSHAKE : Flag::ORDINARY);
        // Random 12 bytes nonce = 32 bits incremental egress msg counter + random 64 bits
        m_nonce = ByteStream((Integer(session->IncrEgressMsgCounter()) << 64) + ByteStream::generateRandom(8).as_Integer(), 12);
        m_authdata_size = 32;
        m_src_ID = getHostENR()->getID();
        if( with_handshake )
            addHandshakeHeader();
    }
    //Encryption is done at the concrete msg level
}

void DiscV5AuthMessage::addHandshakeHeader()
{
    m_flag = Flag::HANDSHAKE;
    m_id_sig_size = 64;
    m_eph_pub_key_size = 33;
    m_enr = getHostENR();
    m_authdata_size = 34 + m_id_sig_size + m_eph_pub_key_size + m_enr->getSignedRLP().byteSize();
    generateHandshakeKeys(m_id_sig, m_eph_pub_key);
}

void DiscV5AuthMessage::generateHandshakeKeys( ByteStream &IDSignature,
                                               Pubkey &ephemeral_pubkey )
{
    if( auto session = dynamic_pointer_cast<const DiscV5Session>(getSessionHandler()) ; session->getENR() )
    {
        ByteStream node_id_a(getHostENR()->getID());
        ByteStream node_id_b(session->getENR()->getID());

        Privkey ephemeral_secret = Privkey::generateRandom();
        ephemeral_pubkey = ephemeral_secret.getPubKey();

        Pubkey ecdh(Secp256k1::GetInstance().p_scalar(session->getENR()->getPubKey().getPoint(), ephemeral_secret.getSecret()));
        ByteStream shared_secret = ecdh.getKey(Pubkey::Format::PREFIXED_X);
        
        ByteStream challenge_data = session->getLastReceivedWhoAreYouMsg()->getChallengeData();

        ByteStream kdf_info("discovery v5 key agreement");
        kdf_info.push_back(node_id_a);
        kdf_info.push_back(node_id_b);

        ByteStream new_key(Integer::zero, 32);
        int retval = hkdf_derive( shared_secret, shared_secret.byteSize(),
                                  challenge_data, challenge_data.byteSize(),
                                  kdf_info, kdf_info.byteSize(),
                                  new_key );
        if(retval > 0)
        {   
            const_pointer_cast<DiscV5Session>(session)->setHostSessionKey(ByteStream(&new_key[0], 16));
            const_pointer_cast<DiscV5Session>(session)->setPeerSessionKey(ByteStream(&new_key[16], 16));

            ByteStream id_signature_input("discovery v5 identity proof");
            id_signature_input.push_back(challenge_data);
            id_signature_input.push_back(ephemeral_pubkey.getKey(Pubkey::Format::PREFIXED_X));
            id_signature_input.push_back(node_id_b);
            Signature sig(getHostENR()->getSecret()->sign(id_signature_input.sha256()));

            IDSignature.clear();
            IDSignature.push_back(ByteStream(sig.get_r(), 32));
            IDSignature.push_back(ByteStream(sig.get_s(), 32));
        }
    }
}

void DiscV5AuthMessage::extractHandshakeKeys()
{
    if( auto session = dynamic_pointer_cast<const DiscV5Session>(getSessionHandler()) ; session->getENR() )
    {
        ByteStream node_id_a(session->getENR()->getID());
        ByteStream node_id_b(getHostENR()->getID());

        Pubkey ecdh(Secp256k1::GetInstance().p_scalar(getEphemeralPubKey().getPoint(), getHostENR()->getSecret()->getSecret()));
        ByteStream shared_secret = ecdh.getKey(Pubkey::Format::PREFIXED_X);
        
        ByteStream challenge_data = session->getLastSentWhoAreYouMsg()->getChallengeData();

        ByteStream kdf_info("discovery v5 key agreement");
        kdf_info.push_back(node_id_a);
        kdf_info.push_back(node_id_b);

        ByteStream new_key(Integer::zero, 32);
        int retval = hkdf_derive( shared_secret, shared_secret.byteSize(),
                                challenge_data, challenge_data.byteSize(),
                                kdf_info, kdf_info.byteSize(),
                                new_key );
        if(retval > 0)
        {   
            const_pointer_cast<DiscV5Session>(session)->setPeerSessionKey(ByteStream(&new_key[0], 16));
            const_pointer_cast<DiscV5Session>(session)->setHostSessionKey(ByteStream(&new_key[16], 16));

            /*ByteStream id_signature_input("discovery v5 identity proof");
            id_signature_input.push_back(challenge_data);
            id_signature_input.push_back(getEphemeralPubKey().getKey(Pubkey::Format::PREFIXED_X));
            id_signature_input.push_back(node_id_b);
            Signature sig(getHostENR()->getSecret()->sign(id_signature_input.sha256()));*/
        }
    }
}

void DiscV5AuthMessage::encryptMessage()
{
    m_authdata.clear();
    m_authdata.push_back(getSourceID());
    if( getFlag() == Flag::HANDSHAKE )
    {
        m_authdata.push_back(getIDSignatureSize());
        m_authdata.push_back(getEphemeralPubKeySize());
        m_authdata.push_back(getIDSignature());
        m_authdata.push_back(getEphemeralPubKey().getKey(Pubkey::Format::PREFIXED_X));
        m_authdata.push_back(getENR()->getSignedRLP());
    }

    if( auto session = dynamic_pointer_cast<const DiscV5Session>(getSessionHandler()) )
    {
        //Add type in front of RLP payload
        ByteStream pt(getRLPPayload());
        pt.ByteStream::push_front(getType(), 1);

        ByteStream aad;
        aad.push_back(getMaskingIV());
        aad.push_back(getHeader());

        ByteStream ciphertext(Integer::zero, pt.byteSize());
        ByteStream tag(Integer::zero, 16);

        // Encrypt Type + RLPPayload and postfix GCM tag => m_message_data
        gcm_encrypt(pt, pt.byteSize(),
                    aad, aad.byteSize(),
                    session->getHostSessionKey(),
                    getNonce(), getNonce().byteSize(),
                    ciphertext, tag);
        
        m_message_data.clear();
        m_message_data.push_back(ciphertext);
        //There is a 16-bytes Tag that is postfixed to the ciphertext
        m_message_data.push_back(tag);
    }

    DiscV5UnauthMessage::encryptMessage();
}

const string DiscV5AuthMessage::getName() const
{
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
        return "TALKREQ";
    case 0x06:
        return "TALKRESP";
    default:
        return "UNKNOWN";
    }
}

void DiscV5AuthMessage::print() const
{
    DiscV5UnauthMessage::print();

    cout << "    Source-ID : 0x" << hex << getSourceID() << endl;
    if( getFlag() == Flag::HANDSHAKE )
    {
        cout << "    ID-Signature size : " << dec << (int)getIDSignatureSize() << endl;
        cout << "    Ephemeral PubKey size : " << dec << (int)getEphemeralPubKeySize() << endl;
        cout << "    ID-Signature : 0x" << hex << getIDSignature() << endl;
        cout << "    Ephemeral PubKey : 0x" << hex << getEphemeralPubKey().getKey(Pubkey::Format::PREFIXED_X) << endl;
        if( getENR() )
        {
            cout << "    ENR Record : " << endl;
            getENR()->print();
        }
    }
    cout << "    Type : " << getName() << endl;
}

//--------------------------------------------------------------------------------------------------

//Parsing Constructor
DiscV5PingMessage::DiscV5PingMessage(const shared_ptr<const DiscV5AuthMessage> auth_msg)
    : DiscV5AuthMessage(auth_msg)
{
    bool is_list;
    RLPByteStream rlp(getRLPPayload());
    m_request_id = rlp.pop_front(is_list).as_uint64();
    m_enr_seq = rlp.pop_front(is_list).as_uint64();
}

//Constructor for building msg to send
DiscV5PingMessage::DiscV5PingMessage(const shared_ptr<const SessionHandler> session_handler, const bool with_handshake)
    : DiscV5AuthMessage(session_handler, with_handshake, 0x01)
    , m_enr_seq(getHostENR()->getSeq())
{  
    RAND_bytes(reinterpret_cast<unsigned char*>(&m_request_id), 8);

    m_rlp_payload.clear();
    m_rlp_payload.push_back(ByteStream(getRequestID()));
    m_rlp_payload.push_back(ByteStream(getENRSeq()));

    encryptMessage();
}

void DiscV5PingMessage::print() const
{
    DiscV5AuthMessage::print();

    cout << "    Request-ID : " << dec << getRequestID() << endl;
    cout << "    ENR-Seq : " << dec << getENRSeq() << endl;
    cout << "-----------------------------------------------------------------------------------" << endl;
}

//-------------------------------------------------------------------------------------------------

//Parsing Constructor
DiscV5PongMessage::DiscV5PongMessage(const shared_ptr<const DiscV5AuthMessage> auth_msg)
    : DiscV5AuthMessage(auth_msg)
{
    bool is_list;
    RLPByteStream rlp(getRLPPayload());
    m_request_id = rlp.pop_front(is_list).as_uint64();
    m_enr_seq = rlp.pop_front(is_list).as_uint64();
    m_recipient_ip = rlp.pop_front(is_list).as_uint64();
    m_recipient_udp_port = rlp.pop_front(is_list).as_uint64();
}

//Constructor for building msg to send
DiscV5PongMessage::DiscV5PongMessage(const shared_ptr<const SessionHandler> session_handler, const uint64_t request_id, const bool with_handshake)
    : DiscV5AuthMessage(session_handler, with_handshake, 0x02)
    , m_request_id(request_id)
    , m_enr_seq(getHostENR()->getSeq())
    , m_recipient_ip(ntohl(session_handler->getPeerAddress().sin_addr.s_addr))
    , m_recipient_udp_port(ntohs(session_handler->getPeerAddress().sin_port))
{
    m_rlp_payload.clear();
    m_rlp_payload.push_back(ByteStream(getRequestID()));
    m_rlp_payload.push_back(ByteStream(getENRSeq()));
    m_rlp_payload.push_back(ByteStream(getRecipientIP()));
    m_rlp_payload.push_back(ByteStream(getRecipientUDPPort()));

    encryptMessage();
}

void DiscV5PongMessage::print() const
{
    DiscV5AuthMessage::print();

    cout << "    Request-ID : " << dec << getRequestID() << endl;
    cout << "    ENR-Seq : " << dec << getENRSeq() << endl;
    char ip[INET_ADDRSTRLEN];
    struct sockaddr_in sa;
    sa.sin_addr.s_addr = htonl(getRecipientIP());
    inet_ntop(AF_INET, &(sa.sin_addr), ip, INET_ADDRSTRLEN);
    cout << "    Recipient IP : " << ip << endl;
    cout << "    Recipient UDP Port : " << dec << getRecipientUDPPort() << endl;
    cout << "-----------------------------------------------------------------------------------" << endl;
}

//----------------------------------------------------------------------------------------------------------

//Parsing Constructor
DiscV5FindNodeMessage::DiscV5FindNodeMessage(const shared_ptr<const DiscV5AuthMessage> auth_msg)
    : DiscV5AuthMessage(auth_msg)
{
    bool is_list;
    RLPByteStream rlp(getRLPPayload());
    m_request_id = rlp.pop_front(is_list).as_uint64();
    while( rlp.byteSize() > 1 )
        m_log2_distance_list.push_back(rlp.pop_front(is_list).as_uint8());
}

//Constructor for building msg to send
DiscV5FindNodeMessage::DiscV5FindNodeMessage(const shared_ptr<const SessionHandler> session_handler, const vector<uint16_t> &log2_distance_list, const bool with_handshake)
    : DiscV5AuthMessage(session_handler, with_handshake, 0x03)
    , m_log2_distance_list(log2_distance_list)
{
    RAND_bytes(reinterpret_cast<unsigned char*>(&m_request_id), 8);

    m_rlp_payload.clear();
    m_rlp_payload.push_back(ByteStream(), true);
    for(int i=0;i<m_log2_distance_list.size();i++)
        m_rlp_payload.push_back(m_log2_distance_list[i] ? ByteStream(m_log2_distance_list[i]) : ByteStream());
    m_rlp_payload.push_front(ByteStream(getRequestID()), true);
    cout << m_rlp_payload << endl;

    encryptMessage();
}

void DiscV5FindNodeMessage::print() const
{
    DiscV5AuthMessage::print();

    cout << "    Request-ID : " << dec << getRequestID() << endl;
    cout << "    Log2 Distance List : ";
    for(int i=0;i<m_log2_distance_list.size();i++)
        cout << dec << (int)m_log2_distance_list[i] << " ";
    cout << endl;
    cout << "-----------------------------------------------------------------------------------" << endl;
}

//----------------------------------------------------------------------------------------------------------

//Parsing Constructor
DiscV5NeighborsMessage::DiscV5NeighborsMessage(const shared_ptr<const DiscV5AuthMessage> auth_msg)
    : DiscV5AuthMessage(auth_msg)
{
    bool is_list;
    RLPByteStream rlp(getRLPPayload());
    m_request_id = rlp.pop_front(is_list).as_uint64();
    m_total = rlp.pop_front(is_list).as_uint64();
    RLPByteStream enr_list = rlp.pop_front(is_list);
    while( enr_list.byteSize() > 2 )
        m_enr_list.push_back(make_shared<ENRV4Identity>(enr_list.pop_front(is_list)));
}

//Constructor for building msg to send
DiscV5NeighborsMessage::DiscV5NeighborsMessage(const shared_ptr<const SessionHandler> session_handler, const uint64_t request_id, const vector<shared_ptr<const ENRV4Identity>> &enr_list, const bool with_handshake)
    : DiscV5AuthMessage(session_handler, with_handshake, 0x04)
    , m_request_id(request_id)
    , m_total(enr_list.size())
    , m_enr_list(enr_list)
{  
    m_rlp_payload.clear();
    for(int i=0;i<m_enr_list.size();i++)
        m_rlp_payload.push_back(m_enr_list[i]->getSignedRLP());
    m_rlp_payload.push_front(ByteStream(getTotal()), true);
    m_rlp_payload.push_front(ByteStream(getRequestID()), true);

    encryptMessage();
}

void DiscV5NeighborsMessage::print() const
{
    DiscV5AuthMessage::print();

    cout << "    Request-ID : " << dec << getRequestID() << endl;
    cout << "    Total : " << dec << getTotal() << endl;
    for(int i=0;i<m_enr_list.size();i++)
        m_enr_list[i]->print();
    cout << "-----------------------------------------------------------------------------------" << endl;
}
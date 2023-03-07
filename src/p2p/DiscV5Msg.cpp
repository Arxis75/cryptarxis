#include "DiscV5Msg.h"
#include "DiscV5.h"
#include "Network.h"

#include <crypto/AES.h>

#include <openssl/rand.h>   //RAND_bytes

#include <iostream>         //cout

using std::cout;
using std::hex;
using std::dec;
using std::endl;
using std::dynamic_pointer_cast;

#define EXPIRATION_DELAY_IN_SEC 20

DiscV5UnauthMessage::DiscV5UnauthMessage(const shared_ptr<const DiscV5UnauthMessage> unmasked_header_msg)
    : DiscoveryMessage(unmasked_header_msg)
    , m_masking_iv(unmasked_header_msg->m_masking_iv)
    , m_masked_header(unmasked_header_msg->m_masked_header)
    , m_protocol_id(unmasked_header_msg->m_protocol_id)
    , m_version(unmasked_header_msg->m_version)
    , m_flag(unmasked_header_msg->m_flag)
    , m_nonce(unmasked_header_msg->m_nonce)
    , m_authdata_size(unmasked_header_msg->m_authdata_size)
    , m_header(unmasked_header_msg->m_header)
    , m_message_data(unmasked_header_msg->m_message_data)
{ }

DiscV5UnauthMessage::DiscV5UnauthMessage(const shared_ptr<const SocketHandler> handler, const vector<uint8_t> buffer, const struct sockaddr_in &peer_addr, const bool is_ingress)
    : DiscoveryMessage(handler, buffer, peer_addr, is_ingress)
{   
    //By convention, the unknown Peer is set with an ID = 0x000..000 (over 32 bytes)
    m_peer_ID = ByteStream(Integer::zero, 32);

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

        if( isValid() )
        {
            m_nonce = ByteStream(&unmasked_remainder[9], 12);
            m_authdata_size = ByteStream(&unmasked_remainder[21], 2).as_uint64();

            //Adjust the headers sizes according to authdata_size
            m_masked_header = masked_remainder.pop_front(23 + m_authdata_size);
            m_header = unmasked_remainder.pop_front(23 + m_authdata_size);

            m_message_data = masked_remainder;
        }
    }
}

DiscV5UnauthMessage::DiscV5UnauthMessage(const shared_ptr<const SessionHandler> session_handler, const Flag flag, const ByteStream &request_nonce)
    : DiscoveryMessage(session_handler)
    , m_flag(flag)
{
    if( auto session = const_pointer_cast<DiscV5Session>(dynamic_pointer_cast<const DiscV5Session>(session_handler)) )
    {
        m_masking_iv = ByteStream::generateRandom(16);

        m_protocol_id = ByteStream("discv5");
        m_version = 0x0001;
        if( m_flag == Flag::WHOAREYOU)
            //the nonce mirrors the request packet's nonce
            m_nonce = request_nonce;
        else
            // Random 12 bytes nonce = 32 bits incremental egress msg counter + random 64 bits
            m_nonce = ByteStream((Integer(session->IncrEgressMsgCounter()) << 64) + ByteStream::generateRandom(8).as_Integer(), 12);
        m_authdata_size = (m_flag == Flag::HANDSHAKE ? 131 + getHostENR()->getSignedRLP().byteSize() : (m_flag == Flag::WHOAREYOU ? 24 : 32));

        // Update the msg content:
        m_header.clear();
        m_header.push_back(m_protocol_id);
        m_header.push_back(ByteStream(Integer(m_version), 2));
        m_header.push_back((uint8_t)m_flag);
        m_header.push_back(m_nonce);       
        m_header.push_back(ByteStream(Integer(m_authdata_size), 2));
    }
}

void DiscV5UnauthMessage::encryptHeader()
{
    if( auto session = dynamic_pointer_cast<const DiscV5Session>(getSessionHandler()) )
    {
        ByteStream masking_key(&session->getENR()->getID()[0], 16);

        m_masked_header.clear();
        m_masked_header.resize(getHeader().byteSize());

        ctr_encrypt( getHeader(), getHeader().byteSize(),
                     masking_key,
                     getMaskingIV(), getMaskingIV().byteSize(),
                     m_masked_header );
    }
}

void DiscV5UnauthMessage::encryptMessage()
{
    encryptHeader();
    encryptData();

    //Fills the final DiscV5 encrypted message content
    clear();
    push_back(getMaskingIV());
    push_back(getMaskedHeader());
    push_back(getMessageData());
}

//-----------------------------------------------------------------------------------------------------

//Parsing Constructor
DiscV5WhoAreYouMessage::DiscV5WhoAreYouMessage(const shared_ptr<const DiscV5UnauthMessage> unmasked_header_msg)
    : DiscV5UnauthMessage(unmasked_header_msg)
{
    if( hasValidSize() )
    {
        m_id_nonce = ByteStream(&getHeader()[23], 16);
        m_enr_seq = ByteStream(&getHeader()[39], 8).as_uint64();
    }
}

//session-embedded empty msg
DiscV5WhoAreYouMessage::DiscV5WhoAreYouMessage(const shared_ptr<const SessionHandler> session_handler, const ByteStream &request_nonce)
    : DiscV5UnauthMessage(session_handler, DiscV5UnauthMessage::Flag::WHOAREYOU, request_nonce)
{
    if( auto session = dynamic_pointer_cast<const DiscV5Session>(session_handler) )
    {
        m_id_nonce = ByteStream::generateRandom(16);
        m_enr_seq = (session->getENR() ? session->getENR()->getSeq() : 0);
        
        // Update the msg content:
        m_header.push_back(m_id_nonce);
        m_header.push_back(m_enr_seq, 8);
        m_message_data.clear();

        encryptMessage();
    }
}

const ByteStream DiscV5WhoAreYouMessage::getChallengeData() const
{
    ByteStream retval = getMaskingIV();
    retval.push_back(getHeader());
    return retval;
}

//-----------------------------------------------------------------------------------------------------

//Copy Constructor
DiscV5AuthMessage::DiscV5AuthMessage(const shared_ptr<const DiscV5AuthMessage> unmasked_msg)
    : DiscV5UnauthMessage(unmasked_msg)
    , m_src_ID(unmasked_msg->m_src_ID)
    , m_id_sig_size(unmasked_msg->m_id_sig_size)
    , m_eph_pub_key_size(unmasked_msg->m_eph_pub_key_size)
    , m_id_sig(unmasked_msg->m_id_sig)
    , m_eph_pub_key(unmasked_msg->m_eph_pub_key)
    , m_enr(unmasked_msg->m_enr)
    , m_type(unmasked_msg->m_type)
    , m_rlp_payload(unmasked_msg->m_rlp_payload)
{
    m_peer_ID = unmasked_msg->m_peer_ID;
}

//Parsing Constructor
DiscV5AuthMessage::DiscV5AuthMessage(const shared_ptr<const DiscV5UnauthMessage> unmasked_header_msg)
    : DiscV5UnauthMessage(unmasked_header_msg)
    , m_id_sig_size(0)
    , m_eph_pub_key_size(0)
    , m_enr(shared_ptr<const ENRV4Identity>(nullptr))
{
    if( auto session  = dynamic_pointer_cast<const DiscV5Session>(getSessionHandler()) )
    {
        m_peer_ID = ByteStream(&getHeader()[23], 32);
        m_src_ID = (isIngress() ? ByteStream(m_peer_ID) : getHostENR()->getID());

        if( getFlag() == Flag::HANDSHAKE )
        {
            m_id_sig_size = getHeader()[55];
            m_eph_pub_key_size = getHeader()[56];
            // id_signature = r || s
            m_id_sig = ByteStream(&getHeader()[57], m_id_sig_size);
            // eph_pubkey = x || y
            m_eph_pub_key = Pubkey(ByteStream(&getHeader()[121], m_eph_pub_key_size), Pubkey::Format::PREFIXED_X);

            extractHandshakeKeys();

            if (getHeader().byteSize() > 154)
            {
                m_enr = make_shared<const ENRV4Identity>(RLPByteStream(&getHeader()[154], getHeader().byteSize() - 154));
                cout << hex << m_enr->getSignedRLP().as_Integer() << endl;
            }
        }

        ByteStream aad;
        aad.push_back(getMaskingIV());
        aad.push_back(getHeader());

        //There is a 16-bytes Tag that is postfixed to the ciphertext
        ByteStream ciphertext(&getMessageData()[0], getMessageData().byteSize() - 16);
        ByteStream tag(&getMessageData()[ciphertext.byteSize()], 16);

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
DiscV5AuthMessage::DiscV5AuthMessage(const shared_ptr<const SessionHandler> session_handler, const Flag flag, const uint8_t type)
    : DiscV5UnauthMessage(session_handler, flag)
    , m_type(type)
{
    if( auto session = dynamic_pointer_cast<const DiscV5Session>(session_handler) )
    {
        m_peer_ID = session->getPeerID();
        
        m_src_ID = (isIngress() ? ByteStream(m_peer_ID) : getHostENR()->getID());
        m_header.push_back(m_src_ID);

        if( flag == Flag::HANDSHAKE && session->getENR() )
        {
            m_id_sig_size = 64;
            m_eph_pub_key_size = 33;
            generateHandshakeKeys(m_id_sig, m_eph_pub_key);
            m_enr = getHostENR();
            cout << hex << m_enr->getSignedRLP().as_Integer() << endl;

            m_header.push_back(m_id_sig_size);
            m_header.push_back(m_eph_pub_key_size);
            m_header.push_back(m_id_sig);
            m_header.push_back(m_eph_pub_key.getKey(Pubkey::Format::PREFIXED_X));
            m_header.push_back(m_enr->getSignedRLP());
        }
    }
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
        
        ByteStream challenge_data = session->getChallengeData();

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
        
        ByteStream challenge_data = session->getChallengeData();

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

void DiscV5AuthMessage::encryptData()
{
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
}
//--------------------------------------------------------------------------------------------------

//Parsing Constructor
DiscV5PingMessage::DiscV5PingMessage(const shared_ptr<const DiscV5AuthMessage> unmasked_msg)
    : DiscV5AuthMessage(unmasked_msg)
    , m_request_id(0)
    , m_enr_seq(0)
{
    bool is_list;
    RLPByteStream rlp(getRLPPayload());
    m_request_id = rlp.pop_front(is_list).as_uint64();
    m_enr_seq = rlp.pop_front(is_list).as_uint64();
}

//Constructor for building msg to send
DiscV5PingMessage::DiscV5PingMessage(const shared_ptr<const SessionHandler> session_handler, const Flag flag, const uint64_t request_id)
    : DiscV5AuthMessage(session_handler, flag, 0x01)
{
    if( auto session = dynamic_pointer_cast<const DiscV5Session>(getSessionHandler()) )
    {
        m_request_id = request_id;
        m_enr_seq = getHostENR()->getSeq();
        
        m_rlp_payload.clear();
        m_rlp_payload.push_back(ByteStream(getRequestID()));
        m_rlp_payload.push_back(ByteStream(getENRSeq()));

        encryptMessage();
    }
}

/*
// "WhoAreYou" Contructor
DiscV5AuthMessage::DiscV5AuthMessage(const shared_ptr<const SessionHandler> session_handler,
                                         const ByteStream &dest_node_id, const ByteStream &mirroring_nonce,
                                         ByteStream &challenge_data,
                                         uint64_t enr_seq)
    : DiscoveryMessage(session_handler)
    , m_is_ingress(false)
{
    ByteStream header;
    header.push_back(0x646973637635);                           // protocol-id = "discv5"
    header.push_back(0x0001, 2);                                // version = 0x0001
    header.push_back(0x01, 1);                                  // flag = 0x01
    header.push_back(mirroring_nonce);                          // nonce from received message
    header.push_back(24, 2);                                    // authdata-size = 24
    header.push_back(ByteStream::generateRandom(16));           // id-nonce
    //header.push_back(ByteStream("0x0102030405060708090a0b0c0d0e0f10", 16, 16)); // test id-nonce
    header.push_back(enr_seq, 8);                               // enr-seq

    ByteStream masking_iv = ByteStream::generateRandom(16);     // masking-iv
    //ByteStream masking_iv("0x00000000000000000000000000000000", 16, 16); // test masking-iv
    ByteStream masking_key(&dest_node_id[0], 16);               // dest-id[:16]
    ByteStream masked_header(Integer::zero, header.byteSize());
    ctr_encrypt( header, header.byteSize(),
                 masking_key,
                 masking_iv, 16,
                 masked_header );
    
    ByteStream packet;
    packet.push_back(masking_iv);
    packet.push_back(masked_header);
    
    m_vect.resize(packet.byteSize(), 0);
    memcpy(&m_vect.data()[0], &packet[0], packet.byteSize());
    
    challenge_data.clear();
    challenge_data.push_back(masking_iv);
    challenge_data.push_back(header);
}

// "Ordinary"/"Handshake" Contructor
DiscV5AuthMessage::DiscV5AuthMessage( const shared_ptr<const SessionHandler> session_handler,
                                          uint32_t &session_egress_msg_counter, const Flag flag,
                                          const ByteStream &host_session_key,
                                          const ByteStream &IDSignature, const ByteStream &ephemeral_pubkey)
    : DiscoveryMessage(session_handler)
    , m_is_ingress(false)
{ 
    assert(flag == Flag::ORDINARY || flag == Flag::HANDSHAKE);
    ByteStream header;
    header.push_back(0x646973637635);       // protocol-id = "discv5"
    header.push_back(0x0001, 2);            // version = 0x0001
    header.push_back((uint8_t)flag, 1);     // flag = 0x01
    session_egress_msg_counter++;           // increment the session egress msg counter
    ByteStream nonce(ByteStream::generateRandom(8).as_Integer() + (Integer(session_egress_msg_counter) << 64), 12);
    header.push_back(nonce);                // nonce  = 32 bits egress counter || 64 bits random number = 12 Bytes
    header.push_back(0, 2);                 // authdata-size reserve, updated at the end
    header.push_back(getHostENR()->getID());     // src-id
    if( flag == Flag::HANDSHAKE)
    {
        header.push_back(IDSignature.byteSize(), 1);                            // id-signature (r||s) size  = 64 bytes
        header.push_back(ephemeral_pubkey.byteSize(), 1);                       // compressed secp256k1 ephemeral-pubkey size = 33 bytes
        header.push_back(IDSignature);                                          // id-signature (r||s)
        header.push_back(ephemeral_pubkey);                                     // compressed secp256k1 ephemeral-pubkey
        header.push_back(getHostENR()->getSignedRLP());
    }
    header[21] = header.byteSize() - 23;    // update authdata-size
}

const ByteStream DiscV5AuthMessage::getMaskingKey() const
{
    ByteStream masking_key;
    if( m_is_ingress )
        masking_key = ByteStream(&getHostENR()->getID()[0], 16);
    else
    {
        auto session = dynamic_pointer_cast<const DiscV5Session>(getSessionHandler());
        if(session && session->getENR() )
            masking_key = ByteStream(session->getENR()->getID()[0], 16);
    }
    return masking_key;
}

const ByteStream DiscV5AuthMessage::getMaskingIV() const
{
    return ByteStream(&(*this)[0], 16);
}

const ByteStream DiscV5AuthMessage::getMaskedHeader() const
{
    return ByteStream(&(*this)[16], size() - 16);
}

const ByteStream DiscV5AuthMessage::getHeader(uint8_t ofs, uint8_t size) const
{
    ByteStream header;
    ByteStream masking_key = getMaskingKey();
    if( masking_key.byteSize() )
    {
        // Header does not include the IV
        ByteStream masked_header = getMaskedHeader();

        // Resize header to match the masked_header size
        header = ByteStream(Integer::zero, masked_header.byteSize());

        int retval = ctr_decrypt( masked_header, masked_header.byteSize(),
                                  masking_key,
                                  getMaskingIV(), 16,
                                  header);
        
        if( retval > 0 )
        {
            // Remove the message data if necessary
            // 23  =  6 of protocol-id
            //      + 2 of version
            //      + 1 of flag
            //      + 12 of nonce
            //      + 2 of authdata-size
            // + authdata-size of authdata 
            header = header.pop_front(23 + ByteStream(header[21], 2).as_uint64());
            //Apply optionnal offset and size
            assert(ofs < header.byteSize() && (ofs + size <= header.byteSize()));
            header = ByteStream(&header[ofs], (size ? size : header.byteSize() - ofs));
        }
    }
    return header;
}

const ByteStream DiscV5AuthMessage::getChallengeData() const
{
    ByteStream challenge_data;
    ByteStream header = getHeader();
    if( header.byteSize() )
    {
        challenge_data.push_back(getMaskingIV());
        challenge_data.push_back(header);
    }
    return challenge_data;
}

int DiscV5AuthMessage::generateHandshakeKeys( const Pubkey &peer_pub_key, 
                                                ByteStream &ephemeral_pubkey,
                                                ByteStream &host_session_key, ByteStream &peer_session_key,
                                                ByteStream &IDSignature ) const
{
    int retval = -1;

    ByteStream node_id_a(getHostENR()->getID());
    ByteStream node_id_b(peer_pub_key.getID());

    Privkey ephemeral_secret = Privkey::generateRandom();
    ephemeral_pubkey = ephemeral_secret.getPubKey().getKey(Pubkey::Format::PREFIXED_X);

    Pubkey ecdh(Secp256k1::GetInstance().p_scalar(peer_pub_key.getPoint(), ephemeral_secret.getSecret()));
    ByteStream shared_secret = ecdh.getKey(Pubkey::Format::PREFIXED_X);
    
    ByteStream challenge_data = getChallengeData();

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
        host_session_key = ByteStream(&new_key[0], 16);
        peer_session_key = ByteStream(&new_key[16], 16);

        ByteStream id_signature_input("discovery v5 identity proof");
        id_signature_input.push_back(challenge_data);
        id_signature_input.push_back(ephemeral_pubkey);
        id_signature_input.push_back(node_id_b);
        Signature sig(getHostENR()->getSecret()->sign(id_signature_input.sha256()));

        IDSignature.clear();
        IDSignature.push_back(ByteStream(sig.get_r(), 32));
        IDSignature.push_back(ByteStream(sig.get_s(), 32));
    }
    return retval;
}

const shared_ptr<const ENRV4Identity> DiscV5AuthMessage::getENR() const
{
    ByteStream enr_record = getHeader(57 + getIDSignatureSize() + getEphemeralPubKeySize());
    if( enr_record.byteSize() )
    {
        auto enr = make_shared<const ENRV4Identity>(RLPByteStream(&enr_record[0], enr_record.byteSize()));
        //Validate the record signature against the known SourceID:
        if( enr->getID() == getSourceID() && enr->hasValidSignature() )
            return enr;
    }
    return shared_ptr<const ENRV4Identity>(nullptr);
}

*/
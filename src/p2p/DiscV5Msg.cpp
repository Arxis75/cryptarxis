#include "DiscV5Msg.h"
#include "DiscV5.h"
#include "Network.h"

#include <crypto/AES.h>
#include <iostream>         //cout

using std::cout;
using std::hex;
using std::dec;
using std::endl;
using std::dynamic_pointer_cast;

#define EXPIRATION_DELAY_IN_SEC 20

DiscV5MaskedHeader::DiscV5MaskedHeader(const shared_ptr<const DiscV5MaskedHeader> masked_header)
    : DiscoveryMessage(masked_header)
    , m_iv(masked_header->m_iv)
    , m_protocol(masked_header->m_protocol)
    , m_version(masked_header->m_version)
    , m_flag(masked_header->m_flag)
    , m_nonce(masked_header->m_nonce)
    , m_authdata_size(masked_header->m_authdata_size)
    , m_header(masked_header->m_header)
{ }

DiscV5MaskedHeader::DiscV5MaskedHeader(const vector<uint8_t> &buffer)
    : DiscoveryMessage(buffer)
{   
    //By convention, the unknown Peer is set with an ID = 0x00 (1 byte)
    m_sender_ID = ByteStream(Integer::zero, 32);

    if( hasValidSize() )
    {
        m_iv = ByteStream(&buffer[0], 16);
        ByteStream masked_header(&buffer[0], size());
        ByteStream masking_key(&getHostENR()->getID()[0], 16);

        ctr_decrypt( masked_header, masked_header.byteSize(),
                     masking_key,
                     m_iv, m_iv.byteSize(),
                     m_header );

        m_protocol = ByteStream(&buffer[16], 6).as_uint64();
        m_version = ByteStream(&buffer[22], 2).as_uint64();
        m_flag = (Flag)ByteStream(&buffer[24], 1).as_uint8();
        m_nonce = ByteStream(&buffer[25], 12);
        m_authdata_size = ByteStream(&buffer[37], 2).as_uint64();

        if( isValid() )
            m_header = m_header.pop_front(39 + m_authdata_size);
    }
}

DiscV5MaskedHeader::DiscV5MaskedHeader(const shared_ptr<const SessionHandler> session_handler, const Flag flag)
    : DiscoveryMessage(session_handler)
    , m_flag(flag)
{
    // TODO
}

//-----------------------------------------------------------------------------------------------------

//Copy Constructor
DiscV5WhoAreYouMessage::DiscV5WhoAreYouMessage(const shared_ptr<const DiscV5WhoAreYouMessage> whoareyou_msg)
    : DiscV5MaskedHeader(whoareyou_msg)
    , m_id_nonce(whoareyou_msg->m_id_nonce)
    , m_enr_seq(whoareyou_msg->m_enr_seq)
{ }

//Raw msg constructor
DiscV5WhoAreYouMessage::DiscV5WhoAreYouMessage(const vector<uint8_t> &buffer)
    : DiscV5MaskedHeader(buffer)
{
    if( hasValidSize() )
    {
        m_id_nonce = ByteStream(&buffer[39], 16);
        m_enr_seq = ByteStream(&buffer[55], 8).as_uint64();
    }
}

//session-embedded empty msg
DiscV5WhoAreYouMessage::DiscV5WhoAreYouMessage(const shared_ptr<const SessionHandler> session_handler)
    : DiscV5MaskedHeader(session_handler, DiscV5MaskedHeader::Flag::WHOAREYOU)
{ }

//-----------------------------------------------------------------------------------------------------

//Copy Constructor
DiscV5MaskedMessage::DiscV5MaskedMessage(const shared_ptr<const DiscV5MaskedMessage> masked_msg)
    : DiscV5MaskedHeader(masked_msg)
    , m_type(masked_msg->m_type)
    , m_message_data(masked_msg->m_message_data)
{ }

//Raw msg constructor
DiscV5MaskedMessage::DiscV5MaskedMessage(const vector<uint8_t> &buffer)
    : DiscV5MaskedHeader(buffer)
{ }

//session-embedded empty msg
DiscV5MaskedMessage::DiscV5MaskedMessage(const shared_ptr<const SessionHandler> session_handler, const Flag flag, const uint8_t type)
    : DiscV5MaskedHeader(session_handler, flag)
    , m_type(type)
{ }

/*
// "WhoAreYou" Contructor
DiscV5MaskedMessage::DiscV5MaskedMessage(const shared_ptr<const SessionHandler> session_handler,
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
DiscV5MaskedMessage::DiscV5MaskedMessage( const shared_ptr<const SessionHandler> session_handler,
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

const ByteStream DiscV5MaskedMessage::getMaskingKey() const
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

const ByteStream DiscV5MaskedMessage::getMaskingIV() const
{
    return ByteStream(&(*this)[0], 16);
}

const ByteStream DiscV5MaskedMessage::getMaskedHeader() const
{
    return ByteStream(&(*this)[16], size() - 16);
}

const ByteStream DiscV5MaskedMessage::getHeader(uint8_t ofs, uint8_t size) const
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

const ByteStream DiscV5MaskedMessage::getChallengeData() const
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

int DiscV5MaskedMessage::generateHandshakeKeys( const Pubkey &peer_pub_key, 
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

const shared_ptr<const ENRV4Identity> DiscV5MaskedMessage::getENR() const
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
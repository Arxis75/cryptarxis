#include "Messaging.h"

ByteStream DiscV4Message::serialize(const Privkey &secret, RLPByteStream rlp_payload) const
{
    if( m_msg.byteSize() )
        return m_msg;
    else
    {
        RLPByteStream msg = rlp_payload;
        msg.ByteStream::push_front(m_type, 1); //no RLP-encoding for the type
        Signature sig = secret.sign(msg.keccak256());
        msg.ByteStream::push_front(sig.get_imparity());
        msg.ByteStream::push_front(ByteStream(sig.get_s(), 32));
        msg.ByteStream::push_front(ByteStream(sig.get_r(), 32));
        msg.ByteStream::push_front(msg.keccak256());
        return msg;
    }
}

uint8_t DiscV4Message::getPacketType() const
{
    return (m_msg.byteSize() > 97 ? m_msg[97] : 0);
}

bool DiscV4Message::has_valid_hash() const
{
    return (m_msg.byteSize() > 32 ? ByteStream(m_msg[0], 32) == ByteStream(m_msg[32], m_msg.byteSize() - 32).keccak256() : false); 
}

bool DiscV4Message::getPublicKey(Pubkey &key) const
{
    if(m_msg.byteSize() > 96)
    {
        Signature sig(ByteStream(m_msg[32], 32), ByteStream(m_msg[64], 32), ByteStream(m_msg[96], 1));
        return sig.ecrecover(key, ByteStream(m_msg[32], m_msg.byteSize() - 32).keccak256());
    }
    else
        return false;
}
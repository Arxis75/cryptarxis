#pragma once

#include "EthSessionManager.h"

#include <Common.h>
#include <crypto/bips.h>

class EthMessage
{
   public:
        EthMessage();

        const EthSessionManager& getSessionManager() const { return m_node; }

    private:
        EthSessionManager m_node;        
};

// Ping (0x01):
// Pong (0x02):
// FindNode (0x03):
// Neighbors Packet (0x04):
// ENRRequest Packet (0x05):
// ENRResponse Packet (0x06):
class DiscV4Message : public EthMessage
{
    public:
        DiscV4Message(const ByteStream& msg) : m_msg(msg), m_type(msg[97]) {}
        DiscV4Message(const uint8_t type) : m_type(type) {}

        virtual RLPByteStream RLPEncodePayload() const = 0;

        SocketHandlerMessage serialize(RLPByteStream rlp_payload) const
        {
            if( m_msg.byteSize() )
                return m_msg;
            else
            {
                RLPByteStream msg = rlp_payload;
                msg.ByteStream::push_front(m_type, 1); //no RLP-encoding
                Signature sig = getSessionManager().getSecret().sign(msg.keccak256());
                msg.ByteStream::push_front(sig.get_imparity());
                msg.ByteStream::push_front(ByteStream(sig.get_s(), 32));
                msg.ByteStream::push_front(ByteStream(sig.get_r(), 32));
                msg.ByteStream::push_front(msg.keccak256());
                shared_ptr<SocketHandler> s = m.getSocketHandler();
                s.sendMsg();
            }
        }
        
        uint8_t getPacketType() const
        {
            return (m_msg.byteSize() > 97 ? m_msg[97] : 0);
        }

        bool has_valid_hash() const
        {
            return (m_msg.byteSize() > 32 ? ByteStream(m_msg[0], 32) == ByteStream(m_msg[32], msg.byteSize() - 32).keccak256() : false); 
        }
        
        bool getPublicKey(Pubkey &key) const
        {
            if(m_msg.byteSize() > 96)
            {
                Signature sig(ByteStream(m_msg[32], 32), ByteStream(m_msg[64], 32), ByteStream(m_msg[96], 1));
                return sig.ecrecover(key, ByteStream(m_msg[32], m_msg.byteSize() - 32).keccak256());
            }
            else
                return false;
        }

    private:
        const uint8_t m_type;
        const ByteStream m_msg;
};
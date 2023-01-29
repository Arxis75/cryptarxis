#pragma once

#include "EthSessionManager.h"

#include <Common.h>
#include <crypto/bips.h>

// Ping (0x01):
// Pong (0x02):
// FindNode (0x03):
// Neighbors Packet (0x04):
// ENRRequest Packet (0x05):
// ENRResponse Packet (0x06):
class DiscV4Message
{
    public:
        //Ingress constructor
        DiscV4Message(const ByteStream& msg) : m_msg(msg), m_type(msg[97]) {}
        //Egress constructor
        DiscV4Message(const uint8_t type) : m_type(type) {}

        ByteStream serialize(const Privkey &secret, RLPByteStream rlp_payload) const;
        
        uint8_t getPacketType() const;

        bool has_valid_hash() const;
        
        bool getPublicKey(Pubkey &key) const;

    private:
        const uint8_t m_type;
        const ByteStream m_msg;
};
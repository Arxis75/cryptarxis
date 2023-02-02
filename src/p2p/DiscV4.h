#pragma once

#include <reactor/SocketHandler.h>
#include <p2p/Node.h>

#include <Common.h>
#include <crypto/bips.h>

class DiscV4Session;
class DiscV4Message;

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
        DiscV4Message(const ByteStream msg, const shared_ptr<DiscV4Session> peer = 0);
        //Egress constructor
        DiscV4Message(const uint8_t type);

        ByteStream serialize(const Privkey &secret, const RLPByteStream &rlp_payload) const;
        
        uint8_t getPacketType() const;
        bool getPublicKey(Pubkey &key) const;
        
        bool has_valid_hash() const;
        bool has_valid_signature(Pubkey expected_pubkey) const;

    private:
        uint8_t m_type;
        RLPByteStream m_msg;
};

class DiscV4Session: public std::enable_shared_from_this<DiscV4Session>
{
    public:
        DiscV4Session(const std::weak_ptr<const SocketHandler> socket_handler, const sockaddr_in &peer_address);

        void onNewMessage(const shared_ptr<const DiscV4Message> msg_in);

        const ENRV4Identity &getPeerENR() const { return m_peer_enr; }
    
    private:
        ENRV4Identity m_peer_enr;
        const std::weak_ptr<const SocketHandler> m_socket_handler;
};

class DiscV4SessionManager: public SessionManager, public std::enable_shared_from_this<DiscV4SessionManager>
{
    public:
        DiscV4SessionManager(const ENRV4Identity &host_enr);

        void start() const { SessionManager::start(m_host_enr.getUDPPort(), IPPROTO_UDP); }

        virtual void onNewMessage(const shared_ptr<const SocketMessage> msg_in);

        const ENRV4Identity &getHostENR() const { return m_host_enr; }

    protected:
        ENRV4Identity m_host_enr;
        map<uint64_t, shared_ptr<DiscV4Session>> m_peer_session_list;
};
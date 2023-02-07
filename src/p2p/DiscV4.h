#pragma once

#include <Common.h>
#include <crypto/bips.h>
#include <reactor/SocketHandler.h>
#include <vector>

using std::vector;

class DiscV4PingMessage;
class DiscV4PongMessage;
class DiscV4FindNodeMessage;
class DiscV4NeighborsMessage;
class DiscV4ENRRequestMessage;
class DiscV4ENRResponseMessage;

class DiscV4Server: public SocketHandler
{
    public:
        DiscV4Server(const uint16_t binding_port, const int protocol,
                              const int read_buffer_size = 1280, const int write_buffer_size = 1280,
                              const int tcp_connection_backlog_size = 10);
        DiscV4Server(const int socket, const shared_ptr<const SocketHandler> master_handler);

    protected:
        virtual const shared_ptr<SessionHandler> makeSessionHandler(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address);
        virtual const shared_ptr<SocketHandler> makeSocketHandler(const int socket, const shared_ptr<const SocketHandler> master_handler) const;
        virtual const shared_ptr<SocketMessage> makeSocketMessage(const shared_ptr<const SessionHandler> session_handler) const;
};

class Network;

class DiscV4Session: public SessionHandler
{
    public:
        DiscV4Session(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address);

        virtual void onNewMessage(const shared_ptr<const SocketMessage> msg_in);

        void onNewPing(shared_ptr<DiscV4PingMessage> msg);
        void onNewPong(shared_ptr<DiscV4PongMessage> msg);
        void onNewFindNode(shared_ptr<DiscV4FindNodeMessage> msg);
        void onNewNeighbors(shared_ptr<DiscV4NeighborsMessage> msg);
        void onNewENRRequest(shared_ptr<DiscV4ENRRequestMessage> msg);
        void onNewENRResponse(shared_ptr<DiscV4ENRResponseMessage> msg);
    
        void sendPing();
        void sendPong(const ByteStream &ack_hash) const;      
        void sendFindNode() const;
        void sendNeighbors() const;
        void sendENRRequest();
        void sendENRResponse(const ByteStream &ack_hash) const;

        inline const Pubkey &getPubKey() const { return m_pubkey; }
        inline const ByteStream &getLastSentPingHash() const { return m_last_sent_ping_hash; }
        inline const ByteStream &getLastSentENRRequestHash() const { return m_last_sent_enr_request_hash; }

        bool isVerified() const;

    protected:
        friend class Network;   // Network::onNewNodeCandidates() calls initPublicKey
        void initPublicKey(Pubkey &advertised_key) { m_pubkey = advertised_key; }

    private:
        Pubkey m_pubkey;
        ByteStream m_last_sent_ping_hash;
        ByteStream m_last_sent_enr_request_hash;
        time_t m_last_verified_pong;
};

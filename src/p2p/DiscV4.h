#pragma once

#include <Common.h>
#include <crypto/bips.h>
#include <reactor/SocketHandler.h>
#include <vector>

using std::vector;

class DiscV4SignedMessage;
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
class ENRV4Identity;

class DiscV4Session: public SessionHandler
{
    public:
        DiscV4Session(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address);

        virtual void close();
        virtual void onNewMessage(const shared_ptr<const SocketMessage> msg_in);

        void onNewPing(const shared_ptr<const DiscV4PingMessage> msg);
        void onNewPong(const shared_ptr<const DiscV4PongMessage> msg);
        void onNewFindNode(const shared_ptr<const DiscV4FindNodeMessage> msg);
        void onNewNeighbors(const shared_ptr<const DiscV4NeighborsMessage> msg);
        void onNewENRRequest(const shared_ptr<const DiscV4ENRRequestMessage> msg);
        void onNewENRResponse(const shared_ptr<const DiscV4ENRResponseMessage> msg);
    
        void sendPing();
        void sendPong(const ByteStream &ack_hash) const;      
        void sendFindNode() const;
        void sendNeighbors() const;
        void sendENRRequest();
        void sendENRResponse(const ByteStream &ack_hash) const;

        inline const ByteStream &getLastSentPingHash() const { return m_last_sent_ping_hash; }
        inline const ByteStream &getLastSentENRRequestHash() const { return m_last_sent_enr_request_hash; }

        inline const shared_ptr<const ENRV4Identity> getENR() const { return m_ENR; };
        bool isVerified() const;

    protected:
        friend class Network;   // Network::onNewNodeCandidates() calls initPublicKey

        void setENRFromMessage(const shared_ptr<const DiscV4ENRResponseMessage> msg);
        void removeENR();

    private:
        shared_ptr<const ENRV4Identity> m_ENR;
        ByteStream m_last_sent_ping_hash;
        ByteStream m_last_sent_enr_request_hash;
        uint64_t m_last_verified_pong_timestamp;
};

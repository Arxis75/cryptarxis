#pragma once

#include <p2p/Discovery.h>

#include <Common.h>
#include <crypto/bips.h>

class DiscV4SignedMessage;
class DiscV4PingMessage;
class DiscV4PongMessage;
class DiscV4FindNodeMessage;
class DiscV4NeighborsMessage;
class DiscV4ENRRequestMessage;
class DiscV4ENRResponseMessage;

class ENRV4Identity;

class DiscV4Server: public DiscoveryServer
{
    public:
        DiscV4Server( const shared_ptr<const ENRV4Identity> host_enr,
                      const int read_buffer_size = 1374, const int write_buffer_size = 1374 );
    private:          
        virtual const shared_ptr<SessionHandler> makeSessionHandler(const struct sockaddr_in &peer_address);
        virtual const shared_ptr<SocketMessage> makeSocketMessage(const vector<uint8_t> buffer, const struct sockaddr_in &peer_address) const;
};

class DiscV4Session: public DiscoverySession
{
    public:
        DiscV4Session(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address);

        virtual void onNewMessage(const shared_ptr<const SocketMessage> msg_in);

        virtual void sendPing();

        bool isVerified() const;

    protected:
        void onNewPing(const shared_ptr<const DiscV4PingMessage> msg);
        void onNewPong(const shared_ptr<const DiscV4PongMessage> msg);
        void onNewFindNode(const shared_ptr<const DiscV4FindNodeMessage> msg);
        void onNewNeighbors(const shared_ptr<const DiscV4NeighborsMessage> msg);
        void onNewENRRequest(const shared_ptr<const DiscV4ENRRequestMessage> msg);
        void onNewENRResponse(const shared_ptr<const DiscV4ENRResponseMessage> msg);

        void sendPong(const ByteStream &ack_hash);      
        void sendFindNode();
        void sendNeighbors(const ByteStream &target_id);
        void sendENRRequest();
        void sendENRResponse(const ByteStream &ack_hash);

        inline const ByteStream &getLastSentPingHash() const { return m_last_sent_ping_hash; }
        inline const ByteStream &getLastSentENRRequestHash() const { return m_last_sent_enr_request_hash; }

    private:
        ByteStream m_last_sent_ping_hash;
        ByteStream m_last_sent_enr_request_hash;
        uint64_t m_last_verified_pong_timestamp;
};

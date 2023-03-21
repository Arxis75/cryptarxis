#pragma once

#include "Discovery.h"

#include <Common.h>
#include <crypto/bips.h>
#include <reactor/SocketHandler.h>

class DiscV5AuthMessage;
class DiscV5WhoAreYouMessage;
class DiscV5PingMessage;
class DiscV5PongMessage;
/*class DiscV5FindNodeMessage;
class DiscV5NeighborsMessage;
class DiscV5TalkReqMessage;
class DiscV5TalkRespMessage;*/

class DiscV5Server: public DiscoveryServer
{
    public:
        DiscV5Server( const shared_ptr<const ENRV4Identity> host_enr,
                      const int read_buffer_size = 1070, const int write_buffer_size = 1070);   //1070 = 470 header + 4800/8 ENR in NODES Response

        virtual const shared_ptr<SessionHandler> makeSessionHandler(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address, const vector<uint8_t> &peer_id);
        virtual const shared_ptr<SocketMessage> makeSocketMessage(const shared_ptr<const SocketHandler> handler, const vector<uint8_t> buffer, const struct sockaddr_in &peer_addr) const;
};

class DiscV5Session: public DiscoverySession
{
    public:
        DiscV5Session(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address, const vector<uint8_t> &peer_id);

        virtual void onNewMessage(const shared_ptr<const SocketMessage> msg_in);

        uint32_t IncrEgressMsgCounter() { return m_egress_msg_counter++; }
        
        const shared_ptr<const DiscV5WhoAreYouMessage> getLastSentWhoAreYouMsg() const { return m_last_sent_whoareyou_msg; }
        const shared_ptr<const DiscV5WhoAreYouMessage> getLastReceivedWhoAreYouMsg() const { return m_last_received_whoareyou_msg; }

        const ByteStream &getHostSessionKey() const { return m_host_session_key; }
        const ByteStream &getPeerSessionKey() const { return m_peer_session_key; }
        void setHostSessionKey(const ByteStream &host_session_key) { m_host_session_key = host_session_key; }
        void setPeerSessionKey(const ByteStream &peer_session_key) { m_peer_session_key = peer_session_key; }

        const ByteStream &getLastReceivedNonce() const { return m_last_received_nonce; }
        const uint64_t getLastPingRequestID() const { return m_last_ping_request_id; }
        const uint64_t getLastPongRequestID() const { return m_last_pong_request_id; }
        /*const uint64_t getLastFindNodeRequestID() const { return m_last_findnode_request_id; }
        const uint64_t getLastNeighborsRequestID() const { return m_last_neighbors_request_id; }
        const uint64_t getLastTalkReqRequestID() const { return m_last_talkreq_request_id; }
        const uint64_t getLastTalkRespRequestID() const { return m_last_talkresp_request_id; }*/
        uint8_t getLastSentOrdinaryMsgType() const { return m_last_sent_ordinary_msg_type; }
        
        virtual void sendPing() { sendAuthPing(); }
    
    protected:
        void onNewOrdinaryMessage(const shared_ptr<const DiscV5AuthMessage> auth_msg);
        void onNewWhoAreYouMessage(const shared_ptr<const DiscV5WhoAreYouMessage> way_msg);
        void onNewHandshakeMessage(const shared_ptr<const DiscV5AuthMessage> auth_msg);

        void onNewPing(const shared_ptr<const DiscV5PingMessage> msg);
        void onNewPong(const shared_ptr<const DiscV5PongMessage> msg);

        //void onNewFindNode(const shared_ptr<const DiscV5FindNodeMessage> msg);
        //void onNewNeighbors(const shared_ptr<const DiscV5NeighborsMessage> msg);

        void sendWhoAreYou();
        void sendAuthPing(bool with_handshake = false);
        void sendAuthPong(bool with_handshake = false);
        //void sendFindNode() const;
        //void sendNeighbors() const;
        //void sendTalkReq() const;
        //void sendTalkResp() const;

        virtual void sendMessage(std::shared_ptr<const SocketMessage> msg_out);

    private:
        uint32_t m_egress_msg_counter;
        shared_ptr<const DiscV5WhoAreYouMessage> m_last_sent_whoareyou_msg;
        shared_ptr<const DiscV5WhoAreYouMessage> m_last_received_whoareyou_msg;
        ByteStream m_host_session_key;
        ByteStream m_peer_session_key;
        ByteStream m_last_received_nonce;
        uint64_t m_last_ping_request_id;
        uint64_t m_last_pong_request_id;
        /*uint64_t m_last_findnode_request_id;
        uint64_t m_last_neighbors_request_id;
        uint64_t m_last_talkreq_request_id;
        uint64_t m_last_talkresp_request_id;*/
        uint8_t m_last_sent_ordinary_msg_type;
};

#pragma once

#include "Discovery.h"

#include <Common.h>
#include <crypto/bips.h>
#include <reactor/SocketHandler.h>

/*class DiscV5AuthMessage;
class DiscV5PingMessage;
class DiscV5PongMessage;
class DiscV5FindNodeMessage;
class DiscV5NeighborsMessage;
class DiscV5TalkReqMessage;
class DiscV5TalkRespMessage;*/

class DiscV5Server: public DiscoveryServer
{
    public:
        DiscV5Server( const shared_ptr<const ENRV4Identity> host_enr,
                      const int read_buffer_size = 1070, const int write_buffer_size = 1070);   //1070 = 470 header + 4800/8 ENR in NODES Response
    protected:
        virtual const shared_ptr<SessionHandler> makeSessionHandler(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address, const vector<uint8_t> &peer_id);
        virtual const shared_ptr<SocketMessage> makeSocketMessage(const shared_ptr<const SocketHandler> handler, const vector<uint8_t> buffer, const struct sockaddr_in &peer_addr) const;
        virtual const shared_ptr<SocketMessage> makeSocketMessage(const shared_ptr<const SessionHandler> session_handler) const;
};

class DiscV5Session: public DiscoverySession
{
    public:
        DiscV5Session(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address, const vector<uint8_t> &peer_id);

        virtual void onNewMessage(const shared_ptr<const SocketMessage> msg_in);

        uint32_t IncrEgressMsgCounter() { return m_egress_msg_counter++; }
        const ByteStream &getChallengeData() const { return m_challenge_data; }
        void setChallengeData(const ByteStream &challenge_data) { m_challenge_data = challenge_data; }

        const ByteStream &getHostSessionKey() const { return m_host_session_key; }
        const ByteStream &getPeerSessionKey() const { return m_peer_session_key; }
        void setHostSessionKey(const ByteStream &host_session_key) { m_host_session_key = host_session_key; }
        void setPeerSessionKey(const ByteStream &peer_session_key) { m_peer_session_key = peer_session_key; }

        virtual void sendPing() {}
    
    protected:
        //void onNewPing(const shared_ptr<const DiscV5PingMessage> msg);
        //void onNewPong(const shared_ptr<const DiscV5PongMessage> msg);
        //void onNewFindNode(const shared_ptr<const DiscV5FindNodeMessage> msg);
        //void onNewNeighbors(const shared_ptr<const DiscV5NeighborsMessage> msg);
        //void onNewENRRequest(const shared_ptr<const DiscV5ENRRequestMessage> msg);
        //void onNewENRResponse(const shared_ptr<const DiscV5ENRResponseMessage> msg);

        //void sendPong() const;      
        //void sendFindNode() const;
        //void sendNeighbors() const;
        //void sendTalkReq() const;
        //void sendTalkResp() const;

    private:
        uint32_t m_egress_msg_counter;
        ByteStream m_challenge_data;
        ByteStream m_host_session_key;
        ByteStream m_peer_session_key;
};

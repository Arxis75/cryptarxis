#pragma once

#include "Discovery.h"

#include <Common.h>
#include <crypto/bips.h>
#include <reactor/SocketHandler.h>

/*class DiscV5MaskedMessage;
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
        virtual const shared_ptr<SessionHandler> makeSessionHandler(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address);
        virtual const shared_ptr<SocketMessage> makeSocketMessage(const shared_ptr<const SessionHandler> session_handler) const;
};

class DiscV5Session: public DiscoverySession
{
    public:
        DiscV5Session(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address);

        virtual void onNewDiscoveryMessage(const shared_ptr<const DiscoveryMessage> msg_in);

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
};

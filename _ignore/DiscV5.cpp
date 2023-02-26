#include "Network.h"
#include "DiscV5.h"
#include "DiscV5Msg.h"

#include <tools/tools.h>
#include <crypto/AES.h>
#include <chrono>
#include <iostream>         //cout

using std::cout;
using std::hex;
using std::dec;
using std::endl;
using std::dynamic_pointer_cast;

DiscV5Server::DiscV5Server( const shared_ptr<const ENRV4Identity> host_enr,
                            const int read_buffer_size, const int write_buffer_size )
    : DiscoveryServer(host_enr, read_buffer_size, write_buffer_size)
{ }

const shared_ptr<SessionHandler> DiscV5Server::makeSessionHandler(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address)
{
    return make_shared<DiscV5Session>(socket_handler, peer_address);
}

const shared_ptr<SocketMessage> DiscV5Server::makeSocketMessage(const shared_ptr<const SessionHandler> session_handler) const
{
    return make_shared<DiscV5MaskedMessage>(session_handler);
}

//------------------------------------------------------------------------------------------------------

DiscV5Session::DiscV5Session(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address)
    : DiscoverySession(socket_handler, peer_address)
{ }

void onNewDiscoveryMessage(const shared_ptr<const DiscoveryMessage> msg_in)
{
    auto masked_msg = dynamic_pointer_cast<const DiscV5MaskedMessage>(msg_in);
    uint8_t msg_type;

    if( masked_msg &&
        masked_msg->hasValidSize() &&
        masked_msg->hasValidProtocolID() &&
        masked_msg->hasValidVersion() )
    {
        if( auto server = getServer() )
            // Dispatch the node ID to the Server to check if there was already a session for this node ID
            // but with different IP/Port (Roaming).
            server->handleRoaming( masked_msg->getSourceID(),
                                   dynamic_pointer_cast<const DiscV5Session>(shared_from_this()) );

       /*switch( msg_type )
        {
        case 0x01:
            onNewPing(make_shared<const DiscV5PingMessage>(masked_msg));
            break;
        case 0x02:
            onNewPong(make_shared<const DiscV5PongMessage>(masked_msg));
            break;
        case 0x03:
            onNewFindNode(make_shared<const DiscV5FindNodeMessage>(masked_msg));
            break;
        case 0x04:
            onNewNeighbors(make_shared<const DiscV5NeighborsMessage>(masked_msg));
            break;
        case 0x05:
            onNewTalkReq(make_shared<const DiscV5TalkReqMessage>(masked_msg));
            break;
        case 0x06:
            onNewTalkResp(make_shared<const DiscV5TalkRespMessage>(masked_msg));
            break;
        default:
            break;
        }*/
    }
    else
    {
        auto server = dynamic_pointer_cast<const DiscV5Server>(getSocketHandler());
        if(server)
        {
            //Invalid message (signature probably) => blacklist this peer
            const_pointer_cast<DiscV5Server>(server)->blacklist(getPeerAddress());
            //close the session (not the socket though, as it is UDP)
            close();
        }
    }
    cout << "--------------------------------------------------------------- SESSION COUNT = " << dec << getSocketHandler()->getSessionsCount() << endl;  
}


/*void DiscV5Session::onNewPing(const shared_ptr<const DiscV5PingMessage> msg)
{
}

void DiscV5Session::onNewPong(const shared_ptr<const DiscV5PongMessage> msg)
{
}

void DiscV5Session::onNewFindNode(const shared_ptr<const DiscV5FindNodeMessage> msg)
{
}

void DiscV5Session::onNewNeighbors(const shared_ptr<const DiscV5NeighborsMessage> msg)
{
}

void DiscV5Session::onNewTalkReq(const shared_ptr<const DiscV5ENRRequestMessage> msg)
{
}

void DiscV5Session::onNewTalkResp(const shared_ptr<const DiscV5ENRResponseMessage> msg)
{
}

void DiscV5Session::sendPing()
{
}

void DiscV5Session::sendPong() const
{
}

void DiscV5Session::sendFindNode() const
{
}

void DiscV5Session::sendNeighbors() const
{
}

void DiscV5Session::sendTalkReq() const
{
}

void DiscV5Session::sendTalkResp() const
{
}*/

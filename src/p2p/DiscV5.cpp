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

const shared_ptr<SessionHandler> DiscV5Server::makeSessionHandler(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address, const vector<uint8_t> &peer_id)
{
    return make_shared<DiscV5Session>(socket_handler, peer_address, peer_id);
}

const shared_ptr<SocketMessage> DiscV5Server::makeSocketMessage(const shared_ptr<const SocketHandler> handler, const vector<uint8_t> buffer, const struct sockaddr_in &peer_addr) const
{
    return make_shared<DiscV5UnauthMessage>(handler, buffer, peer_addr);
}

const shared_ptr<SocketMessage> DiscV5Server::makeSocketMessage(const shared_ptr<const SessionHandler> session_handler) const
{
    return make_shared<DiscV5UnauthMessage>(session_handler, DiscV5UnauthMessage::Flag::ORDINARY);
}

//------------------------------------------------------------------------------------------------------

DiscV5Session::DiscV5Session(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address, const vector<uint8_t> &peer_id)
    : DiscoverySession(socket_handler, peer_address, peer_id)
{ }

void DiscV5Session::onNewMessage(const shared_ptr<const SocketMessage> msg_in)
{
    if( auto masked_msg = dynamic_pointer_cast<const DiscV5AuthMessage>(msg_in) )
    {
        /*switch( masked_msg->getType() )
        {
        case 0x01:
            onNewPing(make_shared<const DiscV4PingMessage>(masked_msg));
            break;
        case 0x02:
            onNewPong(make_shared<const DiscV4PongMessage>(masked_msg));
            break;
        case 0x03:
            onNewFindNode(make_shared<const DiscV4FindNodeMessage>(masked_msg));
            break;
        case 0x04:
            onNewNeighbors(make_shared<const DiscV4NeighborsMessage>(masked_msg));
            break;
        case 0x05:
            onNewENRRequest(make_shared<const DiscV4ENRRequestMessage>(masked_msg));
            break;
        case 0x06:
            onNewENRResponse(make_shared<const DiscV4ENRResponseMessage>(masked_msg));
            break;
        case default:
            break;
        }*/
    }
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

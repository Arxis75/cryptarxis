#include "Network.h"

#include <p2p/DiscV4.h>
#include <p2p/DiscV4Msg.h>

#include <tools/tools.h>
#include <chrono>
#include <iostream>         //cout

using std::cout;
using std::hex;
using std::dec;
using std::endl;
using std::dynamic_pointer_cast;

DiscV4Server::DiscV4Server( const shared_ptr<const ENRV4Identity> host_enr,
                            const int read_buffer_size, const int write_buffer_size )
    : DiscoveryServer(host_enr, read_buffer_size, write_buffer_size)
{ }

const shared_ptr<SessionHandler> DiscV4Server::makeSessionHandler(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address, const vector<uint8_t> &peer_id)
{
    return make_shared<DiscV4Session>(socket_handler, peer_address, peer_id);
}

const shared_ptr<SocketMessage> DiscV4Server::makeSocketMessage(const vector<uint8_t> &buffer) const
{
    return make_shared<DiscV4SignedMessage>(buffer);
}

const shared_ptr<SocketMessage> DiscV4Server::makeSocketMessage(const shared_ptr<const SessionHandler> session_handler) const
{
    return make_shared<DiscV4SignedMessage>(session_handler);
}

//------------------------------------------------------------------------------------------------------

DiscV4Session::DiscV4Session(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address, const vector<uint8_t> &peer_id)
    : DiscoverySession(socket_handler, peer_address, peer_id)
    , m_last_verified_pong_timestamp(0)
    , m_last_sent_ping_hash(1)
    , m_last_sent_enr_request_hash(1)
{ }

void DiscV4Session::onNewMessage(const shared_ptr<const SocketMessage> msg_in)
{
    // Print the generic msg prompt
    SessionHandler::onNewMessage(msg_in);

    if( auto signed_msg = dynamic_pointer_cast<const DiscV4SignedMessage>(msg_in) )
    {
        switch( signed_msg->getType() )
        {
        case 0x01:
            onNewPing(make_shared<const DiscV4PingMessage>(signed_msg));
            break;
        case 0x02:
            onNewPong(make_shared<const DiscV4PongMessage>(signed_msg));
            break;
        case 0x03:
            onNewFindNode(make_shared<const DiscV4FindNodeMessage>(signed_msg));
            break;
        case 0x04:
            onNewNeighbors(make_shared<const DiscV4NeighborsMessage>(signed_msg));
            break;
        case 0x05:
            onNewENRRequest(make_shared<const DiscV4ENRRequestMessage>(signed_msg));
            break;
        case 0x06:
            onNewENRResponse(make_shared<const DiscV4ENRResponseMessage>(signed_msg));
            break;
        }
    }
}

bool DiscV4Session::isVerified() const
{
    return getUnixTimeStamp() - m_last_verified_pong_timestamp < 43200;  // 43200s = 12 Hours
}

void DiscV4Session::onNewPing(const shared_ptr<const DiscV4PingMessage> msg)
{
    if( msg && msg->hasNotExpired() && 
        msg->getSenderIP() == ntohl(getPeerAddress().sin_addr.s_addr) &&
        msg->getSenderUDPPort() == ntohs(getPeerAddress().sin_port) )
    {
        msg->print();
        sendPong(msg->getHash());

        if( !isVerified() )
            sendPing();
        else
        {
            // Addition of the sender into the local ENR table
            // if he passed the Endpoint Proof (Valid Pong)
            updatePeerENR(make_shared<const DiscV4ENRResponseMessage>(msg)->getENR());

            sendFindNode();
        }
    }
}

void DiscV4Session::onNewPong(const shared_ptr<const DiscV4PongMessage> msg)
{
    if( msg && msg->hasNotExpired() )
    {
        if( msg->hasValidPingHash(m_last_sent_ping_hash) )
        {
            msg->print();
            m_last_verified_pong_timestamp = getUnixTimeStamp();
        }
        else
        {
            m_last_verified_pong_timestamp = 0;
            notifyInvalidSignature();
        }
    }
}

void DiscV4Session::onNewFindNode(const shared_ptr<const DiscV4FindNodeMessage> msg)
{
    if( msg && msg->hasNotExpired() )
    {
        if( isVerified() )
        {
            msg->print();
            sendNeighbors(msg->getTargetID());
        }
        else
            sendPing();
    }
}

void DiscV4Session::onNewNeighbors(const shared_ptr<const DiscV4NeighborsMessage> msg)
{
    if( msg && msg->hasNotExpired() )
    {
        if( isVerified() )
        {
            if( auto server = dynamic_pointer_cast<const DiscV4Server>(getSocketHandler()) )
            {
                msg->print();
                const_pointer_cast<DiscV4Server>(server)->onNewNodeCandidates(msg->getNodes());
                sendENRRequest();
            }
        }
        else
            sendPing();
    }
}

void DiscV4Session::onNewENRRequest(const shared_ptr<const DiscV4ENRRequestMessage> msg)
{
    if( msg && msg->hasNotExpired() )
    {
        if( isVerified() )
        {
            msg->print();
            sendENRResponse(msg->getHash());
        }
        else
            sendPing();
    }
}

void DiscV4Session::onNewENRResponse(const shared_ptr<const DiscV4ENRResponseMessage> msg)
{
    if( msg )
    {
        if( isVerified() )
        {
            //The recipient of the packet should verify that the node record is signed by the public key which signed the response packet
            if( msg->hasValidENRRequestHash(m_last_sent_enr_request_hash) && msg->getENR()->hasValidSignature() )
            {
                msg->print();
                updatePeerENR(msg->getENR());
            }
            else
                notifyInvalidSignature();
        }
        else
            sendPing();  
    }
}

void DiscV4Session::sendPing()
{
    auto msg_out = make_shared<const DiscV4PingMessage>(shared_from_this());
    m_last_sent_ping_hash = msg_out->getHash();
    sendMessage(msg_out);
    msg_out->DiscV4SignedMessage::print();
}

void DiscV4Session::sendPong(const ByteStream &ack_hash) const
{
    auto msg_out = make_shared<const DiscV4PongMessage>(shared_from_this(), ack_hash);
    sendMessage(msg_out);
    msg_out->DiscV4SignedMessage::print();
}

void DiscV4Session::sendFindNode() const
{
    auto msg_out = make_shared<const DiscV4FindNodeMessage>(shared_from_this());
    sendMessage(msg_out);
    msg_out->DiscV4SignedMessage::print();
}

void DiscV4Session::sendNeighbors(const ByteStream &target_id) const
{
    if( auto server = dynamic_pointer_cast<const DiscV4Server>(getSocketHandler()) )
    {
        auto msg_out = make_shared<const DiscV4NeighborsMessage>(shared_from_this(), server->findNeighbors(target_id));
        sendMessage(msg_out);
        msg_out->DiscV4SignedMessage::print();
    }
}

void DiscV4Session::sendENRRequest()
{
    auto msg_out = make_shared<const DiscV4ENRRequestMessage>(shared_from_this());
    m_last_sent_enr_request_hash = msg_out->getHash();
    sendMessage(msg_out);
    msg_out->DiscV4SignedMessage::print();
}

void DiscV4Session::sendENRResponse(const ByteStream &ack_hash) const
{
    auto msg_out = make_shared<const DiscV4ENRResponseMessage>(shared_from_this(), ack_hash);
    sendMessage(msg_out);
    msg_out->DiscV4SignedMessage::print();
}
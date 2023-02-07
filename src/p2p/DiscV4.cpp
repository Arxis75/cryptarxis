#include "Network.h"
#include "DiscV4.h"
#include "DiscV4Msg.h"

#include <tools/tools.h>
#include <chrono>
#include <iostream>         //cout

using std::cout;
using std::hex;
using std::dec;
using std::endl;
using std::dynamic_pointer_cast;

DiscV4Server::DiscV4Server(const uint16_t binding_port, const int protocol,
                                             const int read_buffer_size, const int write_buffer_size,
                                             const int tcp_connection_backlog_size)
    : SocketHandler(binding_port, protocol, read_buffer_size, write_buffer_size, tcp_connection_backlog_size)
{ }

DiscV4Server::DiscV4Server(const int socket, const shared_ptr<const SocketHandler> master_handler)
    : SocketHandler(socket, master_handler)
{ }

const shared_ptr<SocketHandler> DiscV4Server::makeSocketHandler(const int socket, const shared_ptr<const SocketHandler> master_handler) const
{ 
    return make_shared<DiscV4Server>(socket, master_handler);
}

const shared_ptr<SessionHandler> DiscV4Server::makeSessionHandler(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address)
{
    return make_shared<DiscV4Session>(socket_handler, peer_address);
}

const shared_ptr<SocketMessage> DiscV4Server::makeSocketMessage(const shared_ptr<const SessionHandler> session_handler) const
{
    return make_shared<DiscV4SignedMessage>(session_handler);
}

//------------------------------------------------------------------------------------------------------

DiscV4Session::DiscV4Session(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address)
    : SessionHandler(socket_handler, peer_address)
    , m_last_verified_pong(0)   // 00:00, Jan 1 1970 UTC Posix time
{ }

bool DiscV4Session::isVerified() const
{
    return getUnixTimeStamp() - getUnixTimeStamp(&m_last_verified_pong) < 43200;    // 43200s = 12 Hours
}

void DiscV4Session::onNewMessage(const shared_ptr<const SocketMessage> msg_in)
{
    auto signed_msg = dynamic_pointer_cast<const DiscV4SignedMessage>(msg_in);
    uint8_t msg_type = signed_msg->getType();

    if( signed_msg && signed_msg->hasValidSize() &&
        signed_msg->hasValidHash() &&
        signed_msg->hasValidPubKey(m_pubkey) )
    {
        switch( msg_type )
        {
        case 0x01:
            onNewPing(make_shared<DiscV4PingMessage>(signed_msg));
            break;
        case 0x02:
            onNewPong(make_shared<DiscV4PongMessage>(signed_msg));
            break;
        case 0x03:
            onNewFindNode(make_shared<DiscV4FindNodeMessage>(signed_msg));
            break;
        case 0x04:
            onNewNeighbors(make_shared<DiscV4NeighborsMessage>(signed_msg));
            break;
        case 0x05:
            onNewENRRequest(make_shared<DiscV4ENRRequestMessage>(signed_msg));
            break;
        case 0x06:
            onNewENRResponse(make_shared<DiscV4ENRResponseMessage>(signed_msg));
            break;
        default:
            break;
        }
    }
    //else
    //  close();
}

void DiscV4Session::onNewPing(shared_ptr<DiscV4PingMessage> msg)
{
        //const_pointer_cast<DiscV4Server>(server)->sendMsg(signed_msg);     // echo
    //if( msg && msg->hasValidVersion() && msg->hasNotExpired() )
    if( msg && msg->hasNotExpired() )
    {
        cout << "RECEIVING FROM @" << inet_ntoa(getPeerAddress().sin_addr) << ":" << ntohs(getPeerAddress().sin_port) << endl;
        msg->print();
        sendPong(msg->getHash());

        sendPing();
    }
}

void DiscV4Session::onNewPong(shared_ptr<DiscV4PongMessage> msg)
{
    if( msg && msg->hasValidPingHash(m_last_sent_ping_hash) && msg->hasNotExpired() )
    {
        m_last_verified_pong = getUnixTimeStamp();
        cout << "RECEIVING FROM @" << inet_ntoa(getPeerAddress().sin_addr) << ":" << ntohs(getPeerAddress().sin_port) << endl;
        msg->print();

        sendFindNode();
    }
}

void DiscV4Session::onNewFindNode(shared_ptr<DiscV4FindNodeMessage> msg)
{
    if( msg && msg->hasNotExpired() )
    {
        cout << "RECEIVING FROM @" << inet_ntoa(getPeerAddress().sin_addr) << ":" << ntohs(getPeerAddress().sin_port) << endl;
        msg->print();

        sendNeighbors();  
    }
}

void DiscV4Session::onNewNeighbors(shared_ptr<DiscV4NeighborsMessage> msg)
{
    if( msg && msg->hasNotExpired() )
    {
        cout << "RECEIVING FROM @" << inet_ntoa(getPeerAddress().sin_addr) << ":" << ntohs(getPeerAddress().sin_port) << endl;
        msg->print();
        
        Network::GetInstance().onNewNodeCandidates(msg->getRLPNodes());

        sendENRRequest();
    }
}

void DiscV4Session::onNewENRRequest(shared_ptr<DiscV4ENRRequestMessage> msg)
{
    if( msg && msg->hasNotExpired() )
    {
        cout << "RECEIVING FROM @" << inet_ntoa(getPeerAddress().sin_addr) << ":" << ntohs(getPeerAddress().sin_port) << endl;
        msg->print();

        sendENRResponse(ByteStream(&(*msg)[0], msg->size()).keccak256());
    }
}

void DiscV4Session::onNewENRResponse(shared_ptr<DiscV4ENRResponseMessage> msg)
{
    if( msg && msg->hasValidENRRequestHash(m_last_sent_enr_request_hash) )
    {
        cout << "RECEIVING FROM @" << inet_ntoa(getPeerAddress().sin_addr) << ":" << ntohs(getPeerAddress().sin_port) << endl;
        msg->print();
    }
}

void DiscV4Session::sendPing()
{
    auto server = dynamic_pointer_cast<const DiscV4Server>(getSocketHandler());
    if(server)
    {
        auto msg_out = make_shared<const DiscV4PingMessage>(shared_from_this());
        m_last_sent_ping_hash = msg_out->getHash();
        const_pointer_cast<DiscV4Server>(server)->sendMsg(msg_out);

        cout << "SENDING TO @" << inet_ntoa(getPeerAddress().sin_addr) << ":" << ntohs(getPeerAddress().sin_port) << endl;
        msg_out->print();
    }
}
void DiscV4Session::sendPong(const ByteStream &ack_hash) const
{
    auto server = dynamic_pointer_cast<const DiscV4Server>(getSocketHandler());
    if(server)
    {
        auto msg_out = make_shared<const DiscV4PongMessage>(shared_from_this(), ack_hash);
        const_pointer_cast<DiscV4Server>(server)->sendMsg(msg_out);

        cout << "SENDING TO @" << inet_ntoa(getPeerAddress().sin_addr) << ":" << ntohs(getPeerAddress().sin_port) << endl;
        msg_out->print();
    }
}

void DiscV4Session::sendFindNode() const
{
    auto server = dynamic_pointer_cast<const DiscV4Server>(getSocketHandler());
    if(server)
    {
        ByteStream target = Network::GetInstance().getHostENR()->getPubKey().getKey(Pubkey::Format::XY);
        auto msg_out = make_shared<const DiscV4FindNodeMessage>(shared_from_this(), target);
        const_pointer_cast<DiscV4Server>(server)->sendMsg(msg_out);

        cout << "SENDING TO @" << inet_ntoa(getPeerAddress().sin_addr) << ":" << ntohs(getPeerAddress().sin_port) << endl;
        msg_out->print();
    }
}

void DiscV4Session::sendNeighbors() const
{
    auto server = dynamic_pointer_cast<const DiscV4Server>(getSocketHandler());
    if(server)
    {
        auto msg_out = make_shared<const DiscV4NeighborsMessage>(shared_from_this());
        const_pointer_cast<DiscV4Server>(server)->sendMsg(msg_out);

        cout << "SENDING TO @" << inet_ntoa(getPeerAddress().sin_addr) << ":" << ntohs(getPeerAddress().sin_port) << endl;
        msg_out->print();
    }
}

void DiscV4Session::sendENRRequest()
{
    auto server = dynamic_pointer_cast<const DiscV4Server>(getSocketHandler());
    if(server)
    {
        auto msg_out = make_shared<const DiscV4ENRRequestMessage>(shared_from_this());
        m_last_sent_enr_request_hash = ByteStream(&(*msg_out)[0], msg_out->size()).keccak256();
        const_pointer_cast<DiscV4Server>(server)->sendMsg(msg_out);

        cout << "SENDING TO @" << inet_ntoa(getPeerAddress().sin_addr) << ":" << ntohs(getPeerAddress().sin_port) << endl;
        msg_out->print();
    }
}

void DiscV4Session::sendENRResponse(const ByteStream &ack_hash) const
{
    auto server = dynamic_pointer_cast<const DiscV4Server>(getSocketHandler());
    if(server)
    {
        auto msg_out = make_shared<const DiscV4ENRResponseMessage>(shared_from_this(), ack_hash);
        const_pointer_cast<DiscV4Server>(server)->sendMsg(msg_out);

        cout << "SENDING TO @" << inet_ntoa(getPeerAddress().sin_addr) << ":" << ntohs(getPeerAddress().sin_port) << endl;
        msg_out->print();
    }
}

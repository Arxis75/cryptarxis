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

DiscV5Server::DiscV5Server(const uint16_t binding_port, const int protocol,
                                             const int read_buffer_size, const int write_buffer_size)
    : SocketHandler(binding_port, protocol, read_buffer_size, write_buffer_size)
{ }

DiscV5Server::DiscV5Server(const int socket, const shared_ptr<const SocketHandler> master_handler)
    : SocketHandler(socket, master_handler)
{ /*NOT USED WITH UDP*/ }

const shared_ptr<SocketHandler> DiscV5Server::makeSocketHandler(const int socket, const shared_ptr<const SocketHandler> master_handler) const
{ 
    return make_shared<DiscV5Server>(socket, master_handler);
}

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
    : SessionHandler(socket_handler, peer_address)
    , m_ENR(shared_ptr<const ENRV4Identity>(nullptr))
    , m_last_verified_pong_timestamp(0)
{ }

void DiscV5Session::setENRFromMessage(const shared_ptr<const DiscV5ENRResponseMessage> msg)
{
    /*if( msg && msg->getPeerENR() && 
       (!getENR() || (!msg->getPeerENR()->equals(getENR()) && msg->getPeerENR()->getSeq() >= getENR()->getSeq())) 
      )
    {
        // If incoming msg with new/different && more recent ENR:
        // => remove the old one (unregister the session), add the new one, and (re-)registers the session
        removeENR();
        m_ENR = msg->getPeerENR();
        Network::GetInstance().registerENRSession(dynamic_pointer_cast<DiscV5Session>(shared_from_this()));
    }*/
}

void DiscV5Session::removeENR()
{
    /*if( getENR() )
    {
        //Unregister this ENR-Session from the Network
        Network::GetInstance().removeENRSession(getENR()->getPubKey());
        m_ENR.reset();
    }*/
}

void DiscV5Session::close()
{
    /*//removes from the Network ENR-Session list
    removeENR();

    //removes from the server session list => deletes the peer session (session solely owned by the server)
    SessionHandler::close();*/
}

void DiscV5Session::onNewMessage(const shared_ptr<const SocketMessage> msg_in)
{
    /*auto signed_msg = dynamic_pointer_cast<const DiscV5MaskedMessage>(msg_in);
    uint8_t msg_type;

    if( signed_msg &&
        signed_msg->hasValidSize() &&
        signed_msg->hasValidHash() &&
        signed_msg->hasValidType(msg_type) &&
        (!getENR() || signed_msg->getPubKey() == getENR()->getPubKey()) )
    {
        // Dispatch the node ID to the Network to check if there was already a session for this node ID
        // but with different IP/Port (Roaming).
        Network::GetInstance().handleRoaming(signed_msg->getPubKey(), dynamic_pointer_cast<const DiscV5Session>(shared_from_this()));

       switch( msg_type )
        {
        case 0x01:
            onNewPing(make_shared<const DiscV5PingMessage>(signed_msg));
            break;
        case 0x02:
            onNewPong(make_shared<const DiscV5PongMessage>(signed_msg));
            break;
        case 0x03:
            onNewFindNode(make_shared<const DiscV5FindNodeMessage>(signed_msg));
            break;
        case 0x04:
            onNewNeighbors(make_shared<const DiscV5NeighborsMessage>(signed_msg));
            break;
        case 0x05:
            onNewENRRequest(make_shared<const DiscV5ENRRequestMessage>(signed_msg));
            break;
        case 0x06:
            onNewENRResponse(make_shared<const DiscV5ENRResponseMessage>(signed_msg));
            break;
        default:
            break;
        }
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
*/}

bool DiscV5Session::isVerified() const
{
    /*return getUnixTimeStamp() - m_last_verified_pong_timestamp < 43200;  // 43200s = 12 Hours*/
    return false;
}

void DiscV5Session::onNewPing(const shared_ptr<const DiscV5PingMessage> msg)
{
    /*if( msg && msg->hasNotExpired() && 
        msg->getSenderIP() == ntohl(getPeerAddress().sin_addr.s_addr) &&
        msg->getSenderUDPPort() == ntohs(getPeerAddress().sin_port) )
    {
        cout << "RECEIVING FROM @" << inet_ntoa(getPeerAddress().sin_addr) << ":" << ntohs(getPeerAddress().sin_port) << endl;
        msg->print();

        sendPong(msg->getHash());
        
        if( !isVerified() )
            sendPing();
        else
            // Addition of the sender into the local ENR table
            // if he passed the Endpoint Proof (Valid Pong)
            setENRFromMessage(make_shared<const DiscV5ENRResponseMessage>(msg));
    }/*
}

void DiscV5Session::onNewPong(const shared_ptr<const DiscV5PongMessage> msg)
{
    /*if( msg && msg->hasNotExpired() )
    {
        if( msg->hasValidPingHash(m_last_sent_ping_hash) )
        {
            cout << "RECEIVING FROM @" << inet_ntoa(getPeerAddress().sin_addr) << ":" << ntohs(getPeerAddress().sin_port) << endl;
            msg->print();

            m_last_verified_pong_timestamp = getUnixTimeStamp();

            sendFindNode();
        }
        else
        {
            m_last_verified_pong_timestamp = 0;
            sendPing();        
        }
    }*/
}

void DiscV5Session::onNewFindNode(const shared_ptr<const DiscV5FindNodeMessage> msg)
{
    /*if( msg && msg->hasNotExpired() )
    {
        if( isVerified() )
        {
            cout << "RECEIVING FROM @" << inet_ntoa(getPeerAddress().sin_addr) << ":" << ntohs(getPeerAddress().sin_port) << endl;
            msg->print();

            sendNeighbors(msg->getTarget());
        }
        else
            sendPing();
    }*/
}

void DiscV5Session::onNewNeighbors(const shared_ptr<const DiscV5NeighborsMessage> msg)
{
    /*if( msg && msg->hasNotExpired() )
    {
        if( isVerified() )
        {
            cout << "RECEIVING FROM @" << inet_ntoa(getPeerAddress().sin_addr) << ":" << ntohs(getPeerAddress().sin_port) << endl;
            msg->print();

            Network::GetInstance().onNewNodeCandidates(msg->getNodes());

            sendENRRequest();
        }
        else
            sendPing();
    }*/
}

void DiscV5Session::onNewENRRequest(const shared_ptr<const DiscV5ENRRequestMessage> msg)
{
    /*if( msg && msg->hasNotExpired() )
    {
        if( isVerified() )
        {
            cout << "RECEIVING FROM @" << inet_ntoa(getPeerAddress().sin_addr) << ":" << ntohs(getPeerAddress().sin_port) << endl;
            msg->print();

            sendENRResponse(ByteStream(&(*msg)[0], msg->size()).keccak256());
        }
        else
            sendPing();
    }*/
}

void DiscV5Session::onNewENRResponse(const shared_ptr<const DiscV5ENRResponseMessage> msg)
{
    /*if( msg )
    {
        if( isVerified() )
        {
            //The recipient of the packet should verify that the node record is signed by the public key which signed the response packet
            if( msg->hasValidENRRequestHash(m_last_sent_enr_request_hash) && msg->getPeerENR()->hasValidSignature() )
            {
                cout << "RECEIVING FROM @" << inet_ntoa(getPeerAddress().sin_addr) << ":" << ntohs(getPeerAddress().sin_port) << endl;
                msg->print();

                // Addition of the sender into the local ENR table
                setENRFromMessage(msg);
            }
            else
                sendENRRequest();
        }
        else
            sendPing();  
    }*/
}

void DiscV5Session::sendPing()
{
    /*auto server = dynamic_pointer_cast<const DiscV5Server>(getSocketHandler());
    if(server)
    {
        auto msg_out = make_shared<const DiscV5PingMessage>(shared_from_this());
        m_last_sent_ping_hash = msg_out->getHash();
        const_pointer_cast<DiscV5Server>(server)->sendMsg(msg_out);

        cout << "SENDING TO @" << dec << inet_ntoa(getPeerAddress().sin_addr) << ":" << ntohs(getPeerAddress().sin_port) << endl;
        msg_out->print();
    }*/
}

void DiscV5Session::sendPong(const ByteStream &ack_hash) const
{
    /*auto server = dynamic_pointer_cast<const DiscV5Server>(getSocketHandler());
    if(server)
    {
        auto msg_out = make_shared<const DiscV5PongMessage>(shared_from_this(), ack_hash);
        const_pointer_cast<DiscV5Server>(server)->sendMsg(msg_out);

        cout << "SENDING TO @" << dec << inet_ntoa(getPeerAddress().sin_addr) << ":" << ntohs(getPeerAddress().sin_port) << endl;
        msg_out->print();
    }*/
}

void DiscV5Session::sendFindNode() const
{
    /*auto server = dynamic_pointer_cast<const DiscV5Server>(getSocketHandler());
    if(server)
    {
        Pubkey target = Network::GetInstance().getHostENR()->getPubKey();
        auto msg_out = make_shared<const DiscV5FindNodeMessage>(shared_from_this(), target);
        const_pointer_cast<DiscV5Server>(server)->sendMsg(msg_out);

        cout << "SENDING TO @" << dec << inet_ntoa(getPeerAddress().sin_addr) << ":" << ntohs(getPeerAddress().sin_port) << endl;
        msg_out->print();
    }*/
}

void DiscV5Session::sendNeighbors(const Pubkey &target) const
{
    /*auto server = dynamic_pointer_cast<const DiscV5Server>(getSocketHandler());
    if(server)
    {
        auto msg_out = make_shared<const DiscV5NeighborsMessage>(shared_from_this(), Network::GetInstance().findNeighbors(target));
        const_pointer_cast<DiscV5Server>(server)->sendMsg(msg_out);

        cout << "SENDING TO @" << dec << inet_ntoa(getPeerAddress().sin_addr) << ":" << ntohs(getPeerAddress().sin_port) << endl;
        msg_out->print();
    }*/
}

void DiscV5Session::sendENRRequest()
{
    /*auto server = dynamic_pointer_cast<const DiscV5Server>(getSocketHandler());
    if(server)
    {
        auto msg_out = make_shared<const DiscV5ENRRequestMessage>(shared_from_this());
        m_last_sent_enr_request_hash = msg_out->getHash(); //ByteStream(&(*msg_out)[0], msg_out->size()).keccak256();
        const_pointer_cast<DiscV5Server>(server)->sendMsg(msg_out);

        cout << "SENDING TO @" << dec << inet_ntoa(getPeerAddress().sin_addr) << ":" << ntohs(getPeerAddress().sin_port) << endl;
        msg_out->print();
    }*/
}

void DiscV5Session::sendENRResponse(const ByteStream &ack_hash) const
{
    /*auto server = dynamic_pointer_cast<const DiscV5Server>(getSocketHandler());
    if(server)
    {
        auto msg_out = make_shared<const DiscV5ENRResponseMessage>(shared_from_this(), ack_hash);
        const_pointer_cast<DiscV5Server>(server)->sendMsg(msg_out);

        cout << "SENDING TO @" << dec << inet_ntoa(getPeerAddress().sin_addr) << ":" << ntohs(getPeerAddress().sin_port) << endl;
        msg_out->print();
    }*/
}

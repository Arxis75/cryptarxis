#include "Network.h"
#include "DiscV5.h"
#include "DiscV5Msg.h"

#include <tools/tools.h>
#include <crypto/AES.h>
#include <openssl/rand.h>
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

const shared_ptr<SessionHandler> DiscV5Server::makeSessionHandler(const struct sockaddr_in &peer_address)
{
    return make_shared<DiscV5Session>(shared_from_this(), peer_address);
}

const shared_ptr<SocketMessage> DiscV5Server::makeSocketMessage(const vector<uint8_t> buffer, const struct sockaddr_in &peer_address) const
{
    return make_shared<DiscV5UnauthMessage>(shared_from_this(), buffer, peer_address);
}

//------------------------------------------------------------------------------------------------------

DiscV5Session::DiscV5Session(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address)
    : DiscoverySession(socket_handler, peer_address)
    , m_egress_msg_counter(0)
    , m_last_ping_request_id(0)
    , m_last_findnode_request_id(0)
    //, m_last_talkreq_request_id(0)
    , m_last_sent_ordinary_msg_type(0)
{ }

void DiscV5Session::onNewMessage(const shared_ptr<const SocketMessage> msg_in)
{
    auto unauth_msg = dynamic_pointer_cast<const DiscV5UnauthMessage>(msg_in);
    
    if( unauth_msg->isValid() )
    {
        m_last_received_nonce = unauth_msg->getNonce();

        switch( unauth_msg->getFlag() )
        {
        case DiscV5UnauthMessage::Flag::ORDINARY:
            onNewOrdinaryMessage(make_shared<const DiscV5AuthMessage>(unauth_msg));
            break;
        case DiscV5UnauthMessage::Flag::WHOAREYOU:
            onNewWhoAreYouMessage(make_shared<const DiscV5WhoAreYouMessage>(unauth_msg));
            break;
        case DiscV5UnauthMessage::Flag::HANDSHAKE:
            onNewHandshakeMessage(make_shared<const DiscV5AuthMessage>(unauth_msg));
            break;
        }
    }
}

void DiscV5Session::onNewHandshakeMessage(const shared_ptr<const DiscV5AuthMessage> auth_msg)
{
    onNewOrdinaryMessage(auth_msg);
}

void DiscV5Session::onNewOrdinaryMessage(const shared_ptr<const DiscV5AuthMessage> auth_msg)
{
    switch( auth_msg->getType() )
    {
    case 0x01:
        onNewPing(make_shared<const DiscV5PingMessage>(auth_msg));
        break;
    case 0x02:
        onNewPong(make_shared<const DiscV5PongMessage>(auth_msg));
        break;
    case 0x03:
        onNewFindNode(make_shared<const DiscV5FindNodeMessage>(auth_msg));
        break;
    case 0x04:
        onNewNeighbors(make_shared<const DiscV5NeighborsMessage>(auth_msg));
        break;
    /*case 0x05:
        onNewTalkReq(make_shared<const DiscV5TalkReqMessage>(auth_msg));
        break;
    case 0x06:
        onNewTalkResp(make_shared<const DiscV5TalkRespMessage>(auth_msg));
        break;*/
    }
}

void DiscV5Session::onNewWhoAreYouMessage(const shared_ptr<const DiscV5WhoAreYouMessage> way_msg)
{
    way_msg->print();
    m_last_received_whoareyou_msg = way_msg;

    switch( getLastSentOrdinaryMsgType() )
    {
    case 0x01:
        sendAuthPing(true);
        break;
    case 0x02:
        sendAuthPong(true);
        break;
    case 0x03:
        sendAuthFindNode(true);
        break;
    case 0x04:
        sendAuthNeighbors(true);
        break;
    /*case 0x05:
        sendAuthTalkReq(true);
        break;
    case 0x06:
        sendAuthTalkResp(true);
        break;*/
    }
}

//----------------------------------------------------------------------------------------------

void DiscV5Session::onNewPing(const shared_ptr<const DiscV5PingMessage> msg)
{
    msg->print();
    if( !getPeerSessionKey().byteSize() )
        sendWhoAreYou();
    else
    {
        sendAuthPong(msg->getRequestID());
        sendAuthPing();
    }
}

void DiscV5Session::onNewPong(const shared_ptr<const DiscV5PongMessage> msg)
{
    if( msg->getRequestID() == getLastPingRequestID() )
    {
        m_last_ping_request_id = 0;
        msg->print();
        
        sendAuthFindNode(false);
    }
}

void DiscV5Session::onNewFindNode(const shared_ptr<const DiscV5FindNodeMessage> msg)
{
    msg->print();
    if( !getPeerSessionKey().byteSize() )
        sendWhoAreYou();
    else
        sendAuthNeighbors(msg->getRequestID());
}

void DiscV5Session::onNewNeighbors(const shared_ptr<const DiscV5NeighborsMessage> msg)
{
    if( msg->getRequestID() == getLastFindNodeRequestID() )
    {
        msg->print();

        if( auto server = dynamic_pointer_cast<const DiscV5Server>(getSocketHandler()) )
        {
            msg->print();
            const_pointer_cast<DiscV5Server>(server)->onNewNodeCandidates(msg->getENRList());
        }
    }
}

/*void DiscV5Session::onNewTalkReq(const shared_ptr<const DiscV5TalkReqMessage> msg)
{
}

void DiscV5Session::onNewTalkResp(const shared_ptr<const DiscV5TalkRespMessage> msg)
{
}*/

//------------------------------------------------------------------------------------------

void DiscV5Session::sendWhoAreYou()
{
    auto msg_out = make_shared<const DiscV5WhoAreYouMessage>(shared_from_this(), getLastReceivedNonce());

    m_last_sent_whoareyou_msg = msg_out;

    sendMessage(msg_out);
}

void DiscV5Session::sendAuthPing(bool with_handshake)
{
    RAND_bytes(reinterpret_cast<unsigned char*>(&m_last_ping_request_id), 8);

    auto msg_out = make_shared<const DiscV5PingMessage>(shared_from_this(), with_handshake);
    
    m_last_ping_request_id = msg_out->getRequestID();

    sendMessage(msg_out);
}

void DiscV5Session::sendAuthPong(uint64_t request_id, bool with_handshake)
{
    auto msg_out = make_shared<const DiscV5PongMessage>( shared_from_this(), request_id, with_handshake);
    
    sendMessage(msg_out);
}

void DiscV5Session::sendAuthFindNode(bool with_handshake)
{
    RAND_bytes(reinterpret_cast<unsigned char*>(&m_last_findnode_request_id), 8);

    if( auto server = dynamic_pointer_cast<const DiscV5Server>(getSocketHandler()) )
    {
        cout << hex << server->getHostENR()->getID().as_Integer() << endl;
        cout << hex << getENR()->getID().as_Integer() << endl;
        
        //vector<uint16_t> log2_distance_list = {{(uint16_t)(server->getHostENR()->getID().as_Integer() ^ getENR()->getID().as_Integer()).bitsize()}};
        vector<uint16_t> log2_distance_list = {{256}, {255}, {254}, {253}, {252}, {251}, {250}, {249}, {248}, {247}, {246}, {245}, {243}, {242}, {241}, {240} };

        auto msg_out = make_shared<const DiscV5FindNodeMessage>(shared_from_this(), log2_distance_list, with_handshake);

        m_last_findnode_request_id = msg_out->getRequestID();

        sendMessage(msg_out);
    }
}

void DiscV5Session::sendAuthNeighbors(uint64_t request_id, bool with_handshake) const
{
    //vector<ENRV4Identity> enr_list = getHostENR();
    //auto msg_out = make_shared<const DiscV5NeighborsMessage>( shared_from_this(), 
    //                                                          with_handshake ? DiscV5PongMessage::Flag::HANDSHAKE : DiscV5PongMessage::Flag::ORDINARY,
    //                                                          request_id,
    //                                                          enr_list );
    //sendMessage(msg_out);
}

/*void DiscV5Session::sendTalkReq() const
{
}

void DiscV5Session::sendTalkResp() const
{
}*/

void DiscV5Session::sendMessage(shared_ptr<const SocketMessage> msg_out)
{
    auto msg = dynamic_pointer_cast<const DiscV5AuthMessage>(msg_out);
    if( msg && msg->getFlag() == DiscV5UnauthMessage::Flag::ORDINARY )
        // Store the last Ordinary msg sent in case of a resend with handshake is needed
        m_last_sent_ordinary_msg_type = msg->getType();
    
    DiscoverySession::sendMessage(msg_out);
}

#include "Network.h"

#include <p2p/Discovery.h>

using std::cout;
using std::hex;
using std::dec;
using std::endl;
using std::min;

DiscoverySession::DiscoverySession(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address, const vector<uint8_t> &peer_id)
    : SessionHandler(socket_handler, peer_address, peer_id)
    , m_ENR(shared_ptr<const ENRV4Identity>(nullptr))
{ }

void DiscoverySession::sendMessage(std::shared_ptr<const SocketMessage> msg_out) const
{
    SessionHandler::sendMessage(msg_out);
    msg_out->print();
}

void DiscoverySession::notifyInvalidSignature()
{
    if( auto server = dynamic_pointer_cast<const DiscoveryServer>(getSocketHandler()) )
        const_pointer_cast<DiscoveryServer>(server)->onInvalidSignature(dynamic_pointer_cast<DiscoverySession>(shared_from_this()));
}

void DiscoverySession::updatePeerENR(const shared_ptr<const ENRV4Identity> new_enr)
{
    if( getPeerID() == new_enr->getPeerID() )
    {
        if( !getENR() || (getENR()->getSeq() <= new_enr->getSeq()) )
            // Set new ENR or Update on more recent ENR only
            m_ENR = new_enr;
    }
    else
        //The record signature does not match the packet signature
        notifyInvalidSignature();
}

//--------------------------------------------------------------------------------------------------------------------------

DiscoveryServer::DiscoveryServer( const shared_ptr<const ENRV4Identity> host_enr,
                                  const int read_buffer_size, const int write_buffer_size )
    : SocketHandler(host_enr->getUDPPort(), IPPROTO_UDP, read_buffer_size, write_buffer_size)
    , m_host_enr(host_enr)
{ }

void DiscoveryServer::dispatchMessage(const shared_ptr<const SocketMessage> msg)
{
    auto disc_msg = dynamic_pointer_cast<const DiscoveryMessage>(msg);
    auto session = dynamic_pointer_cast<const DiscoverySession>(disc_msg->getSessionHandler());

    if( disc_msg && session )
    {
        if( !disc_msg->isValid() )
        {
            // Invalid message format => blacklist this peer
            // and close the session
            onInvalidSignature(const_pointer_cast<DiscoverySession>(session));
        }
         else 
        {           
            // Call of the default dispatcher:
            // - dispatch the message to the session
            SocketHandler::dispatchMessage(msg);
        }
    }   
    cout << "--------------------------------------------------------------- SESSION COUNT = " << dec << getSessionsCount() << endl;  
}

void DiscoveryServer::onInvalidSignature(const shared_ptr<DiscoverySession> session)
{
    // Upon invalid signature detection:
    // - close the session,
    // - blacklist the peer
    session->close();
    blacklist(true, session->getPeerAddress());
}

void DiscoveryServer::onNewNodeCandidates(const vector<std::shared_ptr<const ENRV4Identity>> &node_list)
{
    for(auto it = begin(node_list);it!=end(node_list);it++)
    {
        if( auto node_i = it->get() )
        {
            // Is it a real peer (not 0.0.0.0:0000) and not me?
            if( node_i->getIP() && node_i->getUDPPort() &&
                node_i->getID() != getHostENR()->getID() )
            {
                struct sockaddr_in peer_address;
                peer_address.sin_family = AF_INET;
                peer_address.sin_addr.s_addr = htonl(node_i->getIP());
                peer_address.sin_port = htons(node_i->getUDPPort()); 

                if( !isBlacklisted(peer_address) )
                {
                    auto session = dynamic_pointer_cast<const DiscoverySession>(getSessionHandler(DiscoverySession::makeKey(peer_address, node_i->getID())));
                    if(!session)
                    {
                        session = dynamic_pointer_cast<const DiscoverySession>(registerSessionHandler(peer_address, node_i->getID()));
                    
                        // Ping the peer
                        const_pointer_cast<DiscoverySession>(session)->sendPing();
                    }
                }
            }
        }
    }
}

vector<shared_ptr<const ENRV4Identity>> DiscoveryServer::findNeighbors(const ByteStream &target_id) const
{
    map<Integer, shared_ptr<const ENRV4Identity>> neighbors_map;
    auto it1 = getSessionList().begin();
    while( it1!= getSessionList().end() )
    {
        if( auto session = dynamic_pointer_cast<const DiscoverySession>(it1->second) ; 
            session->getENR() && session->getENR()->getID() != target_id )     //skip the exact target
        {
            Integer distance = session->getENR()->getID().as_Integer() ^ target_id.as_Integer();
            neighbors_map.insert(std::make_pair(distance, session->getENR()));
        }
        it1++;
    }

    vector<shared_ptr<const ENRV4Identity>> neighbors_vector;
    auto it2 = begin(neighbors_map);
    while( it2!= end(neighbors_map) && neighbors_vector.size() < 16 ) 
    {
        auto enr = it2->second;
        //cout << dec << it2->first << endl;
        neighbors_vector.push_back(enr);
        it2++;
    }
    return neighbors_vector;
}

//-----------------------------------------------------------------------------------------------------------

DiscoveryMessage::DiscoveryMessage(const shared_ptr<const DiscoveryMessage> disc_msg)
    : SocketMessage(disc_msg)
    , m_timestamp(disc_msg->m_timestamp)
{ }

DiscoveryMessage::DiscoveryMessage(const vector<uint8_t> &buffer)
    : SocketMessage(buffer)
    , m_timestamp(getUnixTimeStamp())
{ }

DiscoveryMessage::DiscoveryMessage(const shared_ptr<const SessionHandler> session_handler)
    : SocketMessage(session_handler)
    , m_timestamp(getUnixTimeStamp())
{ }

const shared_ptr<const ENRV4Identity> DiscoveryMessage::getHostENR() const
{
    auto msg = shared_ptr<const ENRV4Identity>(nullptr);
    if( auto session =  dynamic_pointer_cast<const DiscoverySession>(getSessionHandler()) )
        if( auto server = dynamic_pointer_cast<const DiscoveryServer>(session->getSocketHandler()) )
            return server->getHostENR();
    return msg;
}
#include <p2p/Discovery.h>

using std::cout;
using std::hex;
using std::dec;
using std::endl;
using std::min;

DiscoverySession::DiscoverySession(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address)
    : SessionHandler(socket_handler, peer_address)
    , m_ID(ByteStream())
    , m_ENR(shared_ptr<const ENRV4Identity>(nullptr))
{ }

const shared_ptr<const DiscoveryServer> DiscoverySession::getConstServer() const
{
    return dynamic_pointer_cast<const DiscoveryServer>(getSocketHandler());
}
const shared_ptr<DiscoveryServer> DiscoverySession::getServer() const
{
    return const_pointer_cast<DiscoveryServer>(getConstServer());
}

void DiscoverySession::onNewMessage(const shared_ptr<const SocketMessage> msg_in)
{
    if( auto msg = dynamic_pointer_cast<const DiscoveryMessage>(msg_in) )
    {          
        if( getID().byteSize() && msg->getNodeID() != getID() )
            if( auto server = getServer() )
                //Unregister the out-of-date session ID from the server
                server->removeSessionID(getID());
        // Set/Update the session ID
        m_ID = msg->getNodeID();
    }
}

void DiscoverySession::updateENR(const shared_ptr<const ENRV4Identity> new_enr)
{
    // If same ID, allow the update
    if( new_enr->getID() == getID() )
    {
        // update on new or more recent ENR only
        if(( !m_ENR || m_ENR->getSeq() <= new_enr->getSeq()) )
            m_ENR = new_enr;
    }
    else if( auto server = getServer() )
    {
        // If ENR has an invalid signature, notify the server
        server->onInvalidSignature(dynamic_pointer_cast<DiscoverySession>(shared_from_this()));
    }
}

//--------------------------------------------------------------------------------------------------------------------------

DiscoveryServer::DiscoveryServer( const shared_ptr<const ENRV4Identity> host_enr,
                                  const int read_buffer_size, const int write_buffer_size )
    : SocketHandler(host_enr->getUDPPort(), IPPROTO_UDP, read_buffer_size, write_buffer_size)
    , m_host_enr(host_enr)
{ }

DiscoveryServer::DiscoveryServer(const int socket, const shared_ptr<const SocketHandler> master_handler)
    : SocketHandler(socket, master_handler)
{   /*TCP INTERFACE, NOT USED WITH UDP*/    }

const shared_ptr<SocketHandler> DiscoveryServer::makeSocketHandler(const int socket, const shared_ptr<const SocketHandler> master_handler) const
{   /*TCP INTERFACE, NOT USED WITH UDP*/ 
    return shared_ptr<SocketHandler>(nullptr);
}

void DiscoveryServer::dispatchMessage(const shared_ptr<const SocketMessage> msg)
{
    auto disc_msg = dynamic_pointer_cast<const DiscoveryMessage>(msg);
    auto session = disc_msg->getConstSession();

    if( disc_msg && session )
    {
        if( !disc_msg->isValid() )
        {
            // Invalid message format => blacklist this peer
            // and close the session
            blacklist(true, session->getPeerAddress());
            closeSession(session);
        }
         else 
        {
            auto previous_session = getSessionFromID(disc_msg->getNodeID());
            if( !previous_session )
                //Registers a new <NodeID, Session>
                registerSessionID(disc_msg->getNodeID(), session);
            // Check if there was already a recorded ENR session for this node ID
            // but with different IP/Port (Roaming).
            else if( session != previous_session )
                closeSession(previous_session);

            // Dispatch the message to the session:
            // - the session will be responsible for checking
            // the consistency of the msg NodeID with its own
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
    closeSession(session);
    blacklist(true, session->getPeerAddress());
}

void DiscoveryServer::closeSession(const shared_ptr<const DiscoverySession> session)
{
    removeSessionID(session->getID());
    session->close();
}

void DiscoveryServer::onNewNodeCandidates(const vector<std::shared_ptr<const ENRV4Identity>> &node_list)
{
    for(auto it = begin(node_list);it!=end(node_list);it++)
    {
        if( auto node_i = *it )
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
                    auto session = dynamic_pointer_cast<const DiscoverySession>(getSessionHandler(peer_address));
                    if(!session)
                    {
                        // Creates a new session
                        session = dynamic_pointer_cast<const DiscoverySession>(registerSessionHandler(peer_address));
                        // Pings the peer
                        const_pointer_cast<DiscoverySession>(session)->sendPing();
                    }
                }
            }
        }
    }
}

const shared_ptr<const DiscoverySession> DiscoveryServer::getSessionFromID(const ByteStream &node_id) const
{
    auto it = m_session_id_list.find(node_id);
    if( it != m_session_id_list.end() ) 
        return it->second;
    return shared_ptr<const DiscoverySession>(nullptr); 
}

void DiscoveryServer::registerSessionID(const ByteStream &node_id, shared_ptr<const DiscoverySession> session)
{
    m_session_id_list.insert(make_pair(node_id, session));
    cout << "--------------------------------------------------------------- registerSessionID ENR SESSION COUNT = " << dec << m_session_id_list.size() << endl;
}

void DiscoveryServer::removeSessionID(const ByteStream &node_id)
{
    //removes from the ENR session list
    m_session_id_list.erase(node_id);
    cout << "--------------------------------------------------------------- removeSessionID ENR SESSION COUNT = " << dec << m_session_id_list.size() << endl;  
}

vector<std::weak_ptr<const ENRV4Identity>> DiscoveryServer::findNeighbors(const ByteStream &target_id) const
{
    map<Integer, std::weak_ptr<const ENRV4Identity>> neighbors_map;
    auto it1 = m_session_id_list.begin();
    while( it1!= m_session_id_list.end() )
    {
        auto session = it1->second;
        Integer distance = it1->first.as_Integer() ^ target_id.as_Integer();
        neighbors_map.insert(std::make_pair(distance, session->getENR()));
        it1++;
    }

    vector<std::weak_ptr<const ENRV4Identity>> neighbors_vector;
    auto it2 = begin(neighbors_map);
    while( it2!= end(neighbors_map) && neighbors_vector.size() < 16 ) 
    {
        auto enr = it2->second.lock();
        if( enr && enr->getID() != target_id )  //skip the exact target
        {
            //cout << dec << it2->first << endl;
            neighbors_vector.push_back(enr);
        }
        it2++;
    }
    return neighbors_vector;
}

//-----------------------------------------------------------------------------------------------------------

DiscoveryMessage::DiscoveryMessage(const shared_ptr<const DiscoveryMessage> msg)
    : SocketMessage(msg->getSessionHandler())
    , m_timestamp(getUnixTimeStamp())
    , m_vect(msg->m_vect)
{ }

DiscoveryMessage::DiscoveryMessage(const shared_ptr<const SessionHandler> session_handler)
    : SocketMessage(session_handler)
    , m_timestamp(getUnixTimeStamp())
{ }

const shared_ptr<const DiscoveryServer> DiscoveryMessage::getConstServer() const
{
    if( auto session = dynamic_pointer_cast<const DiscoverySession>(getSessionHandler()) )
        return session->getConstServer();
    else
        return shared_ptr<const DiscoveryServer>(nullptr);
}
const shared_ptr<DiscoveryServer> DiscoveryMessage::getServer()
{
    return const_pointer_cast<DiscoveryServer>(getConstServer());
}
const shared_ptr<const DiscoverySession> DiscoveryMessage::getConstSession() const
{
    return dynamic_pointer_cast<const DiscoverySession>(getSessionHandler());
}
const shared_ptr<DiscoverySession> DiscoveryMessage::getSession()
{
    return const_pointer_cast<DiscoverySession>(getConstSession());
}

const shared_ptr<const ENRV4Identity> DiscoveryMessage::getHostENR() const
{
    if( auto server = getConstServer() )
        return server->getHostENR();
    else
        return shared_ptr<const ENRV4Identity>(nullptr);
}

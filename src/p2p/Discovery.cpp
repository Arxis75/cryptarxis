#include "Discovery.h"

using std::cout;
using std::hex;
using std::dec;
using std::endl;
using std::min;

DiscoverySession::DiscoverySession(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address)
    : SessionHandler(socket_handler, peer_address)
{ }

const shared_ptr<const ENRV4Identity> DiscoverySession::getHostENR() const
{
    if( auto server = dynamic_pointer_cast<const DiscoveryServer>(getSocketHandler()) )
        return server->getHostENR();
    else
        return shared_ptr<const ENRV4Identity>(nullptr);
}

void DiscoverySession::setENR(const shared_ptr<const ENRV4Identity> new_enr)
{
    if( !getENR() || getENR()->getSeq() < new_enr->getSeq() )
    {
        // If incoming msg with new/different && more recent ENR:
        // => remove the old one (unregister the session), add the new one, and (re-)registers the session
        removeENR();
        m_ENR = new_enr;
        if( auto server = getServer() )
            server->registerENRSession(dynamic_pointer_cast<const DiscoverySession>(shared_from_this()));
    }
}

void DiscoverySession::removeENR()
{
    if( getENR() )
    {
        //Unregister this ENR-Session
        if( auto server = getServer() )
            server->removeENRSession(getENR()->getID());
        m_ENR.reset();
    }
}

void DiscoverySession::close()
{
    //removes from the ENR-Session list
    removeENR();

    //removes from the server session list => deletes the peer session (session solely owned by the server)
    SessionHandler::close();
}

//--------------------------------------------------------------------------------------------------------------------------

DiscoveryServer::DiscoveryServer( const shared_ptr<const ENRV4Identity> host_enr,
                                  const int read_buffer_size, const int write_buffer_size )
    : SocketHandler(host_enr->getUDPPort(), IPPROTO_UDP, read_buffer_size, write_buffer_size)
    , m_host_enr(host_enr)
{ }

DiscoveryServer::DiscoveryServer(const int socket, const shared_ptr<const SocketHandler> master_handler)
    : SocketHandler(socket, master_handler)
{ /*TCP INTERFACE, NOT USED WITH UDP*/ }

const shared_ptr<SocketHandler> DiscoveryServer::makeSocketHandler(const int socket, const shared_ptr<const SocketHandler> master_handler) const
{ 
    /*TCP INTERFACE, NOT USED WITH UDP*/ 
    return shared_ptr<SocketHandler>(nullptr);
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

bool DiscoveryServer::handleRoaming(const ByteStream &node_id, const shared_ptr<const DiscoverySession> session) const
{
    bool roaming = false;
    auto roaming_session = getENRSession(node_id);
    if( roaming_session && roaming_session != session )
    {
        //We have a previous session with different IP/Port
        //but same nodeID => this is Peer roaming, close the previous session
        const_pointer_cast<DiscoverySession>(roaming_session)->close();
        roaming = true;
    }
    return roaming;
}

const shared_ptr<const DiscoverySession> DiscoveryServer::getENRSession(const ByteStream &node_id) const
{
    auto it = m_enr_session_list.find(node_id);
    if( it != std::end(m_enr_session_list) ) 
        return it->second.lock();
    return shared_ptr<const DiscoverySession>(nullptr); 
}

void DiscoveryServer::registerENRSession(const shared_ptr<const DiscoverySession> session)
{
    if( session && session->getENR() )
    {
        //Insert the session indexed by its Public key
        m_enr_session_list.insert(make_pair(session->getENR()->getID(), session)); 
        cout << "--------------------------------------------------------------- registerENRSession ENR SESSION COUNT = " << dec << m_enr_session_list.size() << endl;  
    }
}

void DiscoveryServer::removeENRSession(const ByteStream &node_id)
{
    //removes from the ENR session list
    m_enr_session_list.erase(node_id);
    cout << "--------------------------------------------------------------- removeENRSession ENR SESSION COUNT = " << dec << m_enr_session_list.size() << endl;  
}

vector<std::weak_ptr<const ENRV4Identity>> DiscoveryServer::findNeighbors(const ByteStream &target_id) const
{
    vector<std::weak_ptr<const ENRV4Identity>> neighbors_vector;

    map<Integer, std::weak_ptr<const ENRV4Identity>> neighbors_map;
    auto it1 = begin(m_enr_session_list);
    while( it1!= end(m_enr_session_list) )
    {
        if(auto session = it1->second.lock() )
        {
            Integer distance = it1->first.as_Integer() ^ target_id.as_Integer();
            neighbors_map.insert(std::make_pair(distance, session->getENR()));
        }
        it1++;
    }

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

DiscoveryMessage::DiscoveryMessage(const shared_ptr<const DiscoveryMessage> signed_msg)
    : SocketMessage(signed_msg->getSessionHandler())
    , m_timestamp(getUnixTimeStamp())
    , m_vect(signed_msg->m_vect)
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

const shared_ptr<const ENRV4Identity> DiscoveryMessage::getHostENR() const
{
    if( auto session = dynamic_pointer_cast<const DiscoverySession>(getSessionHandler()) )
        return session->getHostENR();
    else
        return shared_ptr<const ENRV4Identity>(nullptr);
}

uint64_t DiscoveryMessage::size() const
{
    return m_vect.size();
}

DiscoveryMessage::operator const uint8_t*() const
{
    return m_vect.data();
}

void DiscoveryMessage::push_back(const uint8_t value)
{ 
    m_vect.push_back(value);
}
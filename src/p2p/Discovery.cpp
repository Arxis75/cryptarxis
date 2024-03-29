#include "Network.h"

#include <p2p/Discovery.h>

using std::cout;
using std::dec;
using std::endl;
using std::hex;
using std::min;

DiscoverySession::DiscoverySession(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address)
    : SessionHandler(socket_handler, peer_address)
    , m_ENR(shared_ptr<const ENRV4Identity>(nullptr))
{
}

void DiscoverySession::sendMessage(std::shared_ptr<const SocketMessage> msg_out)
{
    SessionHandler::sendMessage(msg_out);
    msg_out->print();
}

void DiscoverySession::notifyInvalidSignature()
{
    if (auto server = dynamic_pointer_cast<const DiscoveryServer>(getSocketHandler()))
        const_pointer_cast<DiscoveryServer>(server)->onInvalidSignature(dynamic_pointer_cast<DiscoverySession>(shared_from_this()));
}

bool DiscoverySession::updatePeerENR(const shared_ptr<const ENRV4Identity> new_enr, bool force_valid_signature)
{
    bool retval = false;

    //The recipient of the packet should verify that the node record is signed by the public key which signed the response packet
    if( force_valid_signature || new_enr->hasValidSignature() )
    {
        if( (!getENR() || getENR()->getSeq() < new_enr->getSeq()) &&
            new_enr->getIP() == ntohl(getPeerAddress().sin_addr.s_addr) && 
            new_enr->getUDPPort() == ntohs(getPeerAddress().sin_port) )
        {
            // Set new ENR or Update on more recent ENR only
            m_ENR = new_enr;
            retval = true;
        }
    }
    else
        notifyInvalidSignature();
    
    return retval;
}

//--------------------------------------------------------------------------------------------------------------------------

DiscoveryServer::DiscoveryServer(const shared_ptr<const ENRV4Identity> host_enr,
                                 const int read_buffer_size, const int write_buffer_size)
    : SocketHandler(host_enr->getUDPPort(), IPPROTO_UDP, read_buffer_size, write_buffer_size)
    , m_host_enr(host_enr)
{
}

/*const vector<uint8_t> DiscoveryServer::makeSessionKey(const struct sockaddr_in &peer_address, const vector<uint8_t> &peer_id) const
{
    vector<uint8_t> key;
    key.resize(peer_id.size() + 6);
    if( peer_id.size() )
        memcpy(&key[0], &peer_id[0], peer_id.size());
    memcpy(&key[peer_id.size()], &peer_address.sin_addr.s_addr, 4);
    memcpy(&key[peer_id.size() + 4], &peer_address.sin_port, 2);
    return key;
}*/

void DiscoveryServer::dispatchMessage(const shared_ptr<const SocketMessage> msg)
{
    auto disc_msg = dynamic_pointer_cast<const DiscoveryMessage>(msg);
    auto session = dynamic_pointer_cast<const DiscoverySession>(disc_msg->getSessionHandler());

    if (disc_msg && session)
    {
        if (!disc_msg->isValid())
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
    for (auto it = begin(node_list); it != end(node_list); it++)
    {
        if (auto node_i = it->get())
        {
            // Is it not me?
            if( node_i->getIP() != getHostENR()->getIP() &&
                node_i->getUDPPort() != getHostENR()->getUDPPort() )
            {
                struct sockaddr_in peer_address;
                peer_address.sin_family = AF_INET;
                peer_address.sin_addr.s_addr = htonl(node_i->getIP());
                peer_address.sin_port = htons(node_i->getUDPPort());

                if( !isInternalAddress(peer_address) && !isBlacklisted(peer_address) )
                {
                    auto session = dynamic_pointer_cast<const DiscoverySession>(getSessionHandler(makeSessionKey(peer_address)));
                    if( !session && (*it)->hasValidSignature())
                    {
                        session = dynamic_pointer_cast<const DiscoverySession>(registerSessionHandler(peer_address));
                        const_pointer_cast<DiscoverySession>(session)->updatePeerENR(*it);
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
    while (it1 != getSessionList().end())
    {
        if (auto session = dynamic_pointer_cast<const DiscoverySession>(it1->second);
            session->getENR() && session->getENR()->getID() != target_id) // skip the exact target
        {
            Integer distance = session->getENR()->getID().as_Integer() ^ target_id.as_Integer();
            neighbors_map.insert(std::make_pair(distance, session->getENR()));
        }
        it1++;
    }

    vector<shared_ptr<const ENRV4Identity>> neighbors_vector;
    auto it2 = begin(neighbors_map);
    while (it2 != end(neighbors_map) && neighbors_vector.size() < 16)
    {
        auto enr = it2->second;
        // cout << dec << it2->first << endl;
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

DiscoveryMessage::DiscoveryMessage(const shared_ptr<const SocketHandler> handler, const vector<uint8_t> buffer, const struct sockaddr_in &peer_addr, const bool is_ingress)
    : SocketMessage(handler, buffer, peer_addr, is_ingress)
    , m_timestamp(getUnixTimeStamp())
{ }

DiscoveryMessage::DiscoveryMessage(const shared_ptr<const SessionHandler> session_handler)
    : SocketMessage(session_handler)
    , m_timestamp(getUnixTimeStamp())
{ }

const shared_ptr<const ENRV4Identity> DiscoveryMessage::getHostENR() const
{
    auto enr = shared_ptr<const ENRV4Identity>(nullptr);
    if (auto server = dynamic_pointer_cast<const DiscoveryServer>(getSocketHandler()))
        enr = server->getHostENR();
    return enr;
}

void DiscoveryMessage::print() const
{
    cout << "UDP: "<< (isIngress() ? "RECEIVING " : "SENDING ") << dec << size() << " Bytes " << (isIngress() ? "FROM" : "TO") << " @"
        << inet_ntoa(getPeerAddress().sin_addr) << ":" << ntohs(getPeerAddress().sin_port);
    if( auto socket = getSocketHandler() )
        cout << " (socket = " << socket->getSocket() << ")";
    cout << endl;
}
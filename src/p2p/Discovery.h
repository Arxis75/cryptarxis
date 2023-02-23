#pragma once

//#include "Network.h"
#include <reactor/SocketHandler.h>

#include <Common.h>
#include <crypto/bips.h>

class DiscoveryMessage;
class DiscoverySession;
class ENRV4Identity;

class DiscoveryServer: public SocketHandler
{
    public:
        DiscoveryServer( const shared_ptr<const ENRV4Identity> host_enr,
                         const int read_buffer_size = 4096, const int write_buffer_size = 4096);

        const shared_ptr<const ENRV4Identity> getHostENR() const { return m_host_enr; }
        
        void onNewNodeCandidates(const vector<std::shared_ptr<const ENRV4Identity>> &node_list);
        vector<shared_ptr<const ENRV4Identity>> findNeighbors(const ByteStream &target_id) const;

        void onInvalidSignature(const shared_ptr<DiscoverySession> session);

    protected:
        virtual void dispatchMessage(const shared_ptr<const SocketMessage> msg);

    private:
        shared_ptr<const ENRV4Identity> m_host_enr;

        //Represents a collection of sessions sorted by distance
        //array<vector<const std::weak_ptr<const DiscoverySession>>, 256> m_host_buckets;
};

class DiscoveryMessage: public SocketMessage
{
    public:
        //Copy Constructor
        DiscoveryMessage(const shared_ptr<const DiscoveryMessage> disc_msg);
        //Raw msg constructor
        DiscoveryMessage(const vector<uint8_t> &buffer);
        //session-embedded empty msg
        DiscoveryMessage(const shared_ptr<const SessionHandler> session_handler);

        inline const uint64_t getTimeStamp() const { return m_timestamp; }

        virtual inline bool isValid() const = 0;
    
    protected:
        const shared_ptr<const ENRV4Identity> getHostENR() const;
    
    private:
        const uint64_t m_timestamp;
};

class DiscoverySession: public SessionHandler
{
    public:
        DiscoverySession(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address, const vector<uint8_t> &peer_id);

        inline const shared_ptr<const ENRV4Identity> getENR() const { return m_ENR; }
        
        void updatePeerENR(const shared_ptr<const ENRV4Identity> new_enr);
        
        void notifyInvalidSignature();
        
        virtual void sendPing() = 0;

    private:
        // m_ENR represents the record sent by the peer
        // or a pseudo-ENR built from a peer's ping message
        shared_ptr<const ENRV4Identity> m_ENR;
};
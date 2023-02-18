#pragma once

#include "Network.h"
#include <Common.h>
#include <crypto/bips.h>
#include <reactor/SocketHandler.h>
#include <memory>

using std::shared_ptr;

class DiscoveryServer;
class ENRV4Identity;

class DiscoverySession: public SessionHandler
{
    public:
        DiscoverySession(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address);

        virtual void sendPing() = 0;
        virtual void onNewMessage(const shared_ptr<const SocketMessage> msg_in) = 0;
        virtual void close();

        inline const shared_ptr<const ENRV4Identity> getENR() const { return m_ENR; };
        const shared_ptr<const ENRV4Identity> getHostENR() const;

        inline const shared_ptr<const DiscoveryServer> getConstServer() const { return dynamic_pointer_cast<const DiscoveryServer>(getSocketHandler()); }
        inline const shared_ptr<DiscoveryServer> getServer() const { return const_pointer_cast<DiscoveryServer>(getConstServer()); }
        
    protected:
        void setENR(const shared_ptr<const ENRV4Identity> new_enr);
        void removeENR();

    private:
        shared_ptr<const ENRV4Identity> m_ENR;
};

class DiscoveryServer: public SocketHandler
{
    public:
        DiscoveryServer( const shared_ptr<const ENRV4Identity> host_enr,
                         const int read_buffer_size = 4096, const int write_buffer_size = 4096);
        //Connected constructor: for inheritance compliance only:
        DiscoveryServer(const int socket, const shared_ptr<const SocketHandler> master_handler);

        void registerENRSession(const shared_ptr<const DiscoverySession> session);
        const shared_ptr<const DiscoverySession> getENRSession(const ByteStream &node_id) const;               
        void removeENRSession(const ByteStream &node_id);
        
        void onNewNodeCandidates(const vector<std::shared_ptr<const ENRV4Identity>> &node_list);
        
        vector<std::weak_ptr<const ENRV4Identity>> findNeighbors(const ByteStream &target_id) const;

        bool handleRoaming(const ByteStream &node_id, const shared_ptr<const DiscoverySession> session) const;

        const shared_ptr<const ENRV4Identity> getHostENR() const { return m_host_enr.lock(); }

    protected:
        virtual const shared_ptr<SessionHandler> makeSessionHandler(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address) = 0;
        virtual const shared_ptr<SocketHandler> makeSocketHandler(const int socket, const shared_ptr<const SocketHandler> master_handler) const;
        virtual const shared_ptr<SocketMessage> makeSocketMessage(const shared_ptr<const SessionHandler> session_handler) const = 0;
    
    private:
        weak_ptr<const ENRV4Identity> m_host_enr;
        // Represents a map of <NodeID, DiscoverySession> of known DiscVx sessions
        // to find the Session holding the ENR corresponding to a specified node ID.
        map<ByteStream, const weak_ptr<const DiscoverySession>> m_enr_session_list;

        //Represents a collection of sessions sorted by distance
        //array<vector<const std::weak_ptr<const DiscoverySession>>, 256> m_host_buckets;
};

class DiscoveryMessage: public SocketMessage
{
    public:
        //Copy Constructor
        DiscoveryMessage(const shared_ptr<const DiscoveryMessage> signed_msg);
        //Constructor for building msg to send
        DiscoveryMessage(const shared_ptr<const SessionHandler> session_handler);

        inline const uint64_t getTimeStamp() const { return m_timestamp; }
        const shared_ptr<const ENRV4Identity> getHostENR() const;

        const shared_ptr<const DiscoveryServer> getConstServer() const;
        inline const shared_ptr<DiscoveryServer> getServer() const { return const_pointer_cast<DiscoveryServer>(getConstServer()); }
        inline const shared_ptr<const DiscoverySession> getConstSession() const { return dynamic_pointer_cast<const DiscoverySession>(getSessionHandler()); }
        inline const shared_ptr<DiscoverySession> getSession() const { return const_pointer_cast<DiscoverySession>(getConstSession()); }

        virtual uint64_t size() const;
        virtual operator const uint8_t*() const;
        virtual void push_back(const uint8_t value);

    private:
        uint64_t m_timestamp;
        vector<uint8_t> m_vect;
};
#pragma once

#include "Network.h"
#include <reactor/SocketHandler.h>

#include <Common.h>
#include <crypto/bips.h>

class DiscoverySession;
class ENRV4Identity;

class DiscoveryServer: public SocketHandler
{
    public:
        DiscoveryServer( const shared_ptr<const ENRV4Identity> host_enr,
                         const int read_buffer_size = 4096, const int write_buffer_size = 4096);
        //Connected constructor: for inheritance compliance only:
        DiscoveryServer(const int socket, const shared_ptr<const SocketHandler> master_handler);

        const shared_ptr<const ENRV4Identity> getHostENR() const { return m_host_enr.lock(); }

        void registerSessionID(const ByteStream &node_id, const shared_ptr<const DiscoverySession> session);
        const shared_ptr<const DiscoverySession> getSessionFromID(const ByteStream &node_id) const;               
        virtual void removeSessionID(const ByteStream &node_id);
        
        void onNewNodeCandidates(const vector<std::shared_ptr<const ENRV4Identity>> &node_list);
        vector<std::weak_ptr<const ENRV4Identity>> findNeighbors(const ByteStream &target_id) const;

        void onInvalidSignature(const shared_ptr<DiscoverySession> session);
        void closeSession(const shared_ptr<const DiscoverySession> session);

    protected:
        virtual void dispatchMessage(const shared_ptr<const SocketMessage> msg);

        virtual const shared_ptr<SessionHandler> makeSessionHandler(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address) = 0;
        virtual const shared_ptr<SocketHandler> makeSocketHandler(const int socket, const shared_ptr<const SocketHandler> master_handler) const;
        virtual const shared_ptr<SocketMessage> makeSocketMessage(const shared_ptr<const SessionHandler> session_handler) const = 0;
        virtual const shared_ptr<SocketMessage> makeSocketMessage(const shared_ptr<const SocketMessage> msg) const = 0;
    
    private:
        weak_ptr<const ENRV4Identity> m_host_enr;
        // Represents a map of <NodeID, DiscoverySession> of known DiscVx sessions
        // to find the existing session attached to a specific node
        map<ByteStream, const shared_ptr<const DiscoverySession>> m_session_id_list;

        //Represents a collection of sessions sorted by distance
        //array<vector<const std::weak_ptr<const DiscoverySession>>, 256> m_host_buckets;
};

class DiscoverySession: public SessionHandler
{
    public:
        DiscoverySession(const shared_ptr<const SocketHandler> socket_handler, const struct sockaddr_in &peer_address);

        inline const ByteStream &getID() const { return m_ID; }
        inline const shared_ptr<const ENRV4Identity> getENR() const { return m_ENR; };

        const shared_ptr<const DiscoveryServer> getConstServer() const;
        const shared_ptr<DiscoveryServer> getServer() const;

        virtual void onNewMessage(const shared_ptr<const SocketMessage> msg_in);
        // sendPing() might be called under the server authority => public
        virtual void sendPing() = 0;

    protected:
        void updateENR(const shared_ptr<const ENRV4Identity> new_enr);

    private:
        ByteStream m_ID;
        shared_ptr<const ENRV4Identity> m_ENR;
};

class DiscoveryMessage: public SocketMessage
{
    public:
        //Copy Constructor
        DiscoveryMessage(const shared_ptr<const DiscoveryMessage> signed_msg);
        //Constructor for building msg to send
        DiscoveryMessage(const shared_ptr<const SessionHandler> session_handler);

        inline const uint64_t getTimeStamp() const { return m_timestamp; }

        const shared_ptr<const DiscoveryServer> getConstServer() const;
        const shared_ptr<DiscoveryServer> getServer();
        const shared_ptr<const DiscoverySession> getConstSession() const;
        const shared_ptr<DiscoverySession> getSession();

        virtual inline uint64_t size() const { return m_vect.size(); }
        virtual operator const uint8_t*() const { return m_vect.data(); }
        virtual operator uint8_t*() { return m_vect.data(); }
        virtual inline void resize(uint32_t value) { m_vect.resize(value, 0); }
        inline void push_back(const uint8_t value) { m_vect.push_back(value); };

        virtual inline bool isValid() const = 0;
        virtual inline const ByteStream &getNodeID() const = 0;

    protected:
        const shared_ptr<const ENRV4Identity> getHostENR() const;

    private:
        uint64_t m_timestamp;
        vector<uint8_t> m_vect;
};
#pragma once

#include "DiscV4.h"

#include <Common.h>
#include <crypto/bips.h>
#include <map>
#include <array>
#include <vector>

using std::map;
using std::array;
using std::vector;
using Givaro::Integer;

class ENRV4Identity
{
    public:
        ENRV4Identity(const ENRV4Identity&);
        //Peer-sent ENR
        ENRV4Identity(const Pubkey &pub_key, const RLPByteStream &rlp);
        //This node ENR
        ENRV4Identity(const uint32_t ip, const uint16_t tcp_port, const uint16_t udp_port, const char *secret);
        //Peer ENR
        ENRV4Identity(const uint64_t seq, const uint32_t ip, const uint16_t tcp_port, const uint16_t udp_port, const Pubkey & pub_key);

        const uint64_t getTimeStamp() const { return m_timestamp; }
        const uint64_t getSeq() const { return m_seq; }
        const string &getScheme() const { return m_scheme; }
        const uint32_t getIP() const { return m_ip; }
        const uint16_t getTCPPort() const { return m_tcp_port; }
        const uint16_t getUDPPort() const { return m_udp_port; }
        const Integer &getIP6() const { return m_ip6; }
        const uint16_t getTCP6Port() const { return m_tcp6_port; }
        const uint16_t getUDP6Port() const { return m_udp6_port; }
        const shared_ptr<const Privkey> getSecret() const { return m_secret; }
        const Pubkey &getPubKey() const { return m_pubkey; }
        const ByteStream &getID() const { return m_ID; }
        const bool isSigned() const { return m_is_signed; };

        const RLPByteStream getSignedRLP() const { return m_is_signed ? m_signed_rlp : RLPByteStream(); }
        const string getName() const { return base64_url_encode(getSignedRLP()); }

        bool validatePubKey(const Pubkey &key) const { return key == m_pubkey; };
        bool equals(const shared_ptr<const ENRV4Identity> enr) const;
        void print() const;

    protected:
        const Signature sign(const ByteStream &hash) const;

    private:
        uint64_t m_timestamp;
        uint64_t m_seq;
        string m_scheme;
        uint32_t m_ip;
        uint16_t m_tcp_port;
        uint16_t m_udp_port;
        Integer m_ip6;
        uint16_t m_tcp6_port;
        uint16_t m_udp6_port;
        const shared_ptr<const Privkey> m_secret;
        const Pubkey m_pubkey;
        const ByteStream m_ID;
        RLPByteStream m_signed_rlp;
        bool m_is_signed;
};

class Network
{
    private:
        Network();

    public:
        static Network &GetInstance();
        Network(const Network& obj) = delete;

        void start(const uint32_t ip, const uint16_t udp_port, const uint16_t tcp_port, const char *secret, const uint64_t seq = 1);

        const shared_ptr<const ENRV4Identity> getHostENR() const { return m_host_enr; }
        shared_ptr<const DiscV4Server> getDiscV4Server() { return m_udp_server; }

        void onNewNodeCandidates(const RLPByteStream &node_list);

        //const vector<const std::weak_ptr<const DiscV4Session> findNeighbors(ByteStream) const;
        const shared_ptr<const DiscV4Session> findSessionByID(const Pubkey &node_pub_key) const
        {
            auto it = m_enr_session_list.find(node_pub_key.getKey(Pubkey::Format::XY));
            if( it != std::end(m_enr_session_list) ) 
            {
                auto weak_ptr = it->second;
                if( auto session = weak_ptr.lock() )
                    return session;
            }
            return shared_ptr<const DiscV4Session>(nullptr); 
        }

        const shared_ptr<const DiscV4Session> findSessionByAddress(const struct sockaddr_in &node_address) const
        {
            return std::dynamic_pointer_cast<const DiscV4Session>(m_udp_server->getSessionHandler(node_address));
        }

        void registerENRSession(const shared_ptr<const DiscV4Session> session)
        {
            if( session && session->getENR() )
                //Insert the session indexed by its Public key
                m_enr_session_list.insert(make_pair(session->getENR()->getPubKey().getKey(Pubkey::Format::XY), session));   
        }
        
        void removeENRSession(const Pubkey &pub_key)
        {
            //removes from the ENR session list
            m_enr_session_list.erase(pub_key.getKey(Pubkey::Format::XY));
        }

        bool handleRoaming(const Pubkey &pub_key, const shared_ptr<const DiscV4Session> session)
        {
            bool roaming = false;
            auto roaming_session = findSessionByID(pub_key);
            if( roaming_session && roaming_session != session )
            {
                //We have a previous session with different IP/Port
                //but same nodeID => this is Peer roaming, close the previous session
                //and send ping to ensure ENR re-creation
                const_pointer_cast<DiscV4Session>(roaming_session)->close();
                roaming = true;
            }
            return roaming;
        }

    private:
        static Network *m_sInstancePtr;
        shared_ptr<const ENRV4Identity> m_host_enr;
        shared_ptr<DiscV4Server> m_udp_server;
        //shared_ptr<Eth67Server> tcp_server;
        
        //Represents a map of <32bits_node_ID, DiscV4Session> of known sessions
        //array<vector<const std::weak_ptr<const DiscV4Session>>, 256> m_host_buckets;
        
        // Represents a map of <Pubkey_XY, DiscV4Session> of known sessions
        // for a performant search by Pubkey_XY to find the Session holding the ENR
        // corresponding to a specified Pubkey_XY.
        // Nota:
        //  - the search by IP/Port must be be done at the DiscV4Server object level,
        //  - these search must be done when the new peer is responding with a valid PONG (verification),
        //    allowing the deletion of previous session/ENR of same pubkey or of same IP/Port
        //    prior to the registration of the new ENR done along the verification.
        map<const ByteStream, const std::weak_ptr<const DiscV4Session>> m_enr_session_list;
};
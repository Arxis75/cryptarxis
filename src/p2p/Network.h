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
        ENRV4Identity(const RLPByteStream &rlp, const Pubkey &pub_key = Pubkey());
        //This node ENR
        ENRV4Identity(const uint32_t ip, const uint16_t udp_port, const uint16_t tcp_port, const char *secret);
        //Peer ENR
        ENRV4Identity(const uint64_t seq, const uint32_t ip, const uint16_t udp_port, const uint16_t tcp_port, const Pubkey &pub_key);

        inline const uint64_t getTimeStamp() const { return m_timestamp; }
        inline const uint64_t getSeq() const { return m_seq; }
        inline const string &getScheme() const { return m_scheme; }
        inline const uint32_t getIP() const { return m_ip; }
        inline const uint16_t getUDPPort() const { return m_udp_port; }
        inline const uint16_t getTCPPort() const { return m_tcp_port; }
        inline const Integer &getIP6() const { return m_ip6; }
        inline const uint16_t getUDP6Port() const { return m_udp6_port; }
        inline const uint16_t getTCP6Port() const { return m_tcp6_port; }
        inline const shared_ptr<const Privkey> getSecret() const { return m_secret; }
        inline const Pubkey &getPubKey() const { return m_pubkey; }
        inline const ByteStream &getID() const { return m_ID; }
        inline const bool isSigned() const { return m_is_signed; };
        inline const RLPByteStream getSignedRLP() const { return m_is_signed ? m_signed_rlp : RLPByteStream(); }
        
        const string getName() const { return base64_url_encode(getSignedRLP()); }

        bool hasValidSignature() const;
        bool equals(const shared_ptr<const ENRV4Identity> enr) const;
        void print() const;

    protected:
        const Signature sign(const ByteStream &hash) const;

    private:
        uint64_t m_timestamp;
        uint64_t m_seq;
        string m_scheme;
        uint32_t m_ip;
        uint16_t m_udp_port;
        uint16_t m_tcp_port;
        Integer m_ip6;
        uint16_t m_udp6_port;
        uint16_t m_tcp6_port;
        const shared_ptr<const Privkey> m_secret;   //pointer to test nullity (when peer)
        Pubkey m_pubkey;
        ByteStream m_ID;
        RLPByteStream m_unsigned_rlp;
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

        void onNewNodeCandidates(const vector<std::shared_ptr<const ENRV4Identity>> &node_list) const;

        vector<std::weak_ptr<const ENRV4Identity>> findNeighbors(const Pubkey &target) const;
        
        const shared_ptr<const DiscV4Session> findSessionByID(const Pubkey &node_pub_key) const;
        const shared_ptr<const DiscV4Session> findSessionByAddress(const struct sockaddr_in &node_address) const;

        void registerENRSession(const shared_ptr<const DiscV4Session> session);
        void removeENRSession(const Pubkey &pub_key);

        bool handleRoaming(const Pubkey &pub_key, const shared_ptr<const DiscV4Session> session) const;

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
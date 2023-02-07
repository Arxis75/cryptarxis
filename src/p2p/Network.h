#pragma once

#include "DiscV4.h"

#include <Common.h>
#include <crypto/bips.h>
#include <map>

using std::map;
using Givaro::Integer;

class ENRV4Identity
{
    public:
        //Peer-sent ENR
        ENRV4Identity(const Pubkey &pub_key, const RLPByteStream &rlp);
        //This node ENR
        ENRV4Identity(const uint32_t ip, const uint16_t tcp_port, const uint16_t udp_port, const char *secret);
        ~ENRV4Identity();

        const uint64_t getSeq() const { return m_seq; }
        const string &getScheme() const { return m_scheme; }
        const uint32_t getIP() const { return m_ip; }
        const uint16_t getTCPPort() const { return m_tcp_port; }
        const uint16_t getUDPPort() const { return m_udp_port; }
        const Integer &getIP6() const { return m_ip6; }
        const uint16_t getTCP6Port() const { return m_tcp6_port; }
        const uint16_t getUDP6Port() const { return m_udp6_port; }
        const Privkey *getSecret() const { return m_secret; }
        const Pubkey &getPubKey() const { return m_pubkey; }
        const ByteStream &getID() const { return m_ID; }

        const RLPByteStream &getSignedRLP() const { return m_signed_rlp; }
        const string getName() const { return base64_url_encode(getSignedRLP()); }

        bool validatePubKey(const Pubkey &key) const { return key == m_pubkey; };

        void print() const;

    protected:
        const Signature sign(const ByteStream &hash) const;

    private:
        uint64_t m_seq;
        string m_scheme;
        uint32_t m_ip;
        uint16_t m_tcp_port;
        uint16_t m_udp_port;
        Integer m_ip6;
        uint16_t m_tcp6_port;
        uint16_t m_udp6_port;
        const Privkey *m_secret;
        const Pubkey m_pubkey;
        const ByteStream m_ID;
        RLPByteStream m_signed_rlp;
};

class Network
{
    private:
        Network() {}

    public:
        ~Network() { if(m_host_enr) delete m_host_enr;}
        static Network &GetInstance();
        Network(const Network& obj) = delete;

        void start(const uint32_t ip, const uint16_t udp_port, const uint16_t tcp_port, const char *secret, const uint64_t seq = 1);

        const ENRV4Identity *getHostENR() const { return m_host_enr; }
        shared_ptr<DiscV4Server> getDiscV4Server() { return m_udp_server; }

        void onNewNodeCandidates(const RLPByteStream &node_list);

    private:
        static Network *m_sInstancePtr;
        ENRV4Identity *m_host_enr;
        shared_ptr<DiscV4Server> m_udp_server;
        //shared_ptr<Eth67Server> tcp_server;
};
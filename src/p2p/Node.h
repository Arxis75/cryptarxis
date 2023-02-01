#pragma once

#include <reactor/SocketHandler.h>
#include <crypto/bips.h>

class ENRV4Identity
{
    public:
        //Unknown-ENR Peer
        ENRV4Identity(const uint32_t ip, const uint16_t port, const int protocol);
        //Peer-sent ENR
        ENRV4Identity(const RLPByteStream &rlp);
        //This node ENR
        ENRV4Identity(const uint32_t ip, const uint16_t tcp_port, const uint16_t udp_port, const char *secret, const uint64_t seq = 1);
        ~ENRV4Identity();

        const string &getScheme() const { return m_scheme; }
        const uint32_t getIP() const { return m_ip; }
        const uint16_t getTCPPort() const { return m_tcp_port; }
        const uint16_t getUDPPort() const { return m_udp_port; }
        const Privkey *getSecret() const { return m_secret; }
        const Pubkey &getPubKey() const { return m_pubkey; }
        const ByteStream &getID() const { return m_ID; }
        const RLPByteStream &getSignedRLP() const { return m_signed_rlp; }
        const RLPByteStream &getUnsignedRLP() const { return m_unsigned_rlp; }
        const uint64_t getSeq() const { return m_seq; }
        const string &getName() const { return m_name; }

        const Signature sign(const ByteStream &hash) const;
        bool validatePubKey(const Pubkey &key);

    private:
        string m_scheme;
        uint32_t m_ip;
        uint16_t m_tcp_port;
        uint16_t m_udp_port;
        const Privkey *m_secret;
        Integer m_r, m_s;
        Pubkey m_pubkey;
        ByteStream m_ID;
        RLPByteStream m_signed_rlp;
        RLPByteStream m_unsigned_rlp;
        uint64_t m_seq;
        string m_name;
};

/*class EthNode
{
    private:
        EthNode(ENRV4Identity *enr);
    
    public:
        static EthNode& GetInstance(ENRV4Identity *enr);
        EthNode(const EthNode &obj) = delete;

        void startServer(const int master_protocol);

        //const Privkey &getSecret() const { return m_sEnr->getSecret(); }

    private:
        static ENRV4Identity* m_sEnr;
        static EthNode *m_sInstancePtr;
};*/
#pragma once

#include <reactor/SocketHandler.h>
#include <crypto/bips.h>

class EthSessionManager;

class ENRV4Identity
{
    public:
        ENRV4Identity();

        const Privkey &getSecret() const { return m_secret; }

    private:
        uint64_t m_seq;
        Privkey m_secret;
        ByteStream m_ID;
        sockaddr_in m_local_internet_address;
};

class EthNode
{
    private:
        EthNode(const Privkey &secret, const sockaddr_in &local_internet_address);
    
    public:
        static EthNode& GetInstance();
        EthNode(const EthNode &obj) = delete;

        void startServer(const uint16_t master_port, const int master_protocol);

        const Privkey &getSecret() const { return m_enr->getSecret(); }

    protected:
        void EthNode::registerIdentity();

    private:
        ENRV4Identity* m_enr;
        static EthNode *m_sInstancePtr;
};

class EthSessionManager: public SessionManager, public std::enable_shared_from_this<EthSessionManager>
{
    public:
        EthSessionManager(const uint16_t master_port, const int master_protocol);

        virtual void onNewMessage(const shared_ptr<const SocketHandlerMessage> msg_in);
};
#pragma once

#include <reactor/SocketHandler.h>
#include <crypto/bips.h>

class EthSessionManager;

class EthNode: public std::enable_shared_from_this<EthNode>
{
    public:
        EthNode(const Privkey &secret, const sockaddr_in &local_internet_address)
            : m_local_internet_address(local_internet_address)
            , m_seq(0)
            , m_secret(secret)
        {}

        void start(const uint16_t master_port, const int master_protocol, const AbstractMessaging &msging)
        {
            if( shared_ptr<EthSessionManager> server = make_shared<EthSessionManager>(shared_from_this(), master_port, master_protocol) )
                server->start();
        }

        const Privkey &getSecret() const { return m_secret; }

    private:
        //ENR fields:
        uint64_t m_seq;
        Privkey m_secret;
        ByteStream m_ID;
        sockaddr_in m_local_internet_address;
};

class EthSessionManager: public SessionManager
{
    public:
        EthSessionManager(const shared_ptr<EthNode> &node, const uint16_t master_port, const int master_protocol);

        virtual void onNewMessage(const shared_ptr<const SocketHandlerMessage> msg_in);

        const Privkey &getSecret() const { return m_node.getSecret(); }

    private:
        const EthNode m_node;
        SafeQueue<shared_ptr<const SocketHandlerMessage>> m_ingress;
};
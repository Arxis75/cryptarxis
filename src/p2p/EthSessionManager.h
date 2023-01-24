#pragma once

#include <reactor/SocketHandler.h>

class EthSessionManager: public SessionManager
{
    public:
        EthSessionManager(const uint16_t master_port, const int master_protocol);

        virtual void onNewMessage(const shared_ptr<const SocketHandlerMessage> msg_in);

    private:
        int m_master_port;
        int m_master_protocol;
        SafeQueue<shared_ptr<const SocketHandlerMessage>> m_ingress;
};
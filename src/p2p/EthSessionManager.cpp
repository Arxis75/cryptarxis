#include "EthSessionManager.h"

#include <Common.h>
#include <iostream>         //cout, EXIT_FAILURE, NULL

using std::cout;
using std::hex;
using std::dec;
using std::endl;
using std::min;

EthSessionManager::EthSessionManager(const uint16_t master_port, const int master_protocol)
    : SessionManager(master_port, master_protocol)
{ }

void EthSessionManager::onNewMessage(const shared_ptr<const SocketHandlerMessage> msg_in) 
{
    if(msg_in)
    {
        m_ingress.enqueue(msg_in);
        if( auto sh_in = msg_in->getSocketHandler() )
            cout << dec << "@ " << (sh_in->getProtocol() == IPPROTO_TCP ? "TCP" : "UDP") << " socket = " << sh_in->getSocket()
                    << " => @" << inet_ntoa(msg_in->getPeerAddress().sin_addr) << ":" << ntohs(msg_in->getPeerAddress().sin_port)
                    << ", " << msg_in->data().size() << " Bytes received" << endl;
    }

    //Worker job:
    auto msg = m_ingress.dequeue(); //echo server here for example
    if(msg)
    {   
        bool is_list;
        RLPByteStream rlp(&msg->data()[0], msg->data().size());
        cout << "hash = " << hex << rlp.pop_front(is_list).as_Integer() << endl;
        cout << "r = " << hex << rlp.pop_front(is_list).as_Integer() << endl;
        cout << "s = " << hex << rlp.pop_front(is_list).as_Integer() << endl;
        cout << "y = " << hex << rlp.pop_front(is_list).as_Integer() << endl;
        
        if( auto sh_out = msg->getSocketHandler() )
            if( auto sm_out = sh_out->getSessionManager() )
                const_pointer_cast<SocketHandler>(sh_out)->sendMsg(msg);
    }
}
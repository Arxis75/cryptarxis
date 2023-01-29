#include "EthSessionManager.h"

#include <Common.h>
#include <crypto/bips.h>
#include <iostream>         //cout, EXIT_FAILURE, NULL

using std::cout;
using std::hex;
using std::dec;
using std::endl;
using std::min;

EthSessionManager::EthSessionManager(const EthNode &node,const uint16_t master_port, const int master_protocol)
    : SessionManager(master_port, master_protocol)
    , m_node(node)
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
        
        RLPByteStream rlp(&msg->data()[0], msg->data().size());

        cout << hex << rlp.as_Integer() << endl;
        ByteStream h = rlp.ByteStream::pop_front(32);
        cout << hex << h << endl;

        bool valid_h = (h == rlp.keccak256());

        cout << "Is valid = " << valid_h << endl;

        ByteStream r = rlp.ByteStream::pop_front(32);
        cout << hex << r << endl;
        ByteStream s = rlp.ByteStream::pop_front(32);
        cout << hex << s << endl;
        ByteStream y = rlp.ByteStream::pop_front(1);
        cout << hex << y << endl;

        Pubkey key;
        Signature sig(r,s,y);
        sig.ecrecover(key,rlp.keccak256());

        cout << "PubKey = " << key.getKey(Pubkey::Format::XY) << endl;

        ByteStream msg_id = rlp.ByteStream::pop_front(1);
        cout << hex << msg_id << endl;
        
        bool is_list;
        RLPByteStream field = rlp.pop_front(is_list);
        while(rlp.byteSize() > 0)
        {    
            if(is_list)
            {
                RLPByteStream list = field;
                cout << "[" << endl;
                while( list.byteSize() > 0 )
                {
                    bool is_list2;
                    field = list.pop_front(is_list2);
                    cout << hex << field.as_Integer() << endl;
                }
                cout << "]" << endl;
            }
            else
                cout << hex << field.as_Integer() << endl;
            field = rlp.pop_front(is_list);
        }
        if( auto sh_out = msg->getSocketHandler() )
            if( auto sm_out = sh_out->getSessionManager() )
                const_pointer_cast<SocketHandler>(sh_out)->sendMsg(msg);    //test echo
    }
}
#include "EthSessionManager.h"

#include <Common.h>
#include <crypto/bips.h>
#include <iostream>         //cout, EXIT_FAILURE, NULL

using std::cout;
using std::hex;
using std::dec;
using std::endl;
using std::min;

#define NODE_BIP39_MNC "agree turn detail assume express sheriff buzz dinner jungle method drift brush bless talent army rude secret mercy dilemma cluster climb foot duck dizzy"
#define NODE_BIP39_MNC_PWD "Cryptarxis75"
#define NODE_BIP32_ACCOUNT_NBR 0

EthNode::EthNode(const Privkey &secret, const sockaddr_in &local_internet_address)
    : m_seq(0)
{}

void EthNode::startServer(const uint16_t master_port, const int master_protocol)
{
    if( shared_ptr<EthSessionManager> server = make_shared<EthSessionManager>(master_port, master_protocol) )
        server->start();
}

void EthNode::registerIdentity()
{
    //Should be done from file/cli parameters
    BIP39::Mnemonic mnc(256);
    mnc.set_full_word_list(NODE_BIP39_MNC);
    ByteStream seed = mnc.get_seed(NODE_BIP39_MNC_PWD);
    m_secret = Privkey(seed, "m");
    m_secret = Privkey(m_secret, 44, true);
    m_secret = Privkey(m_secret, 60, true);
    m_secret = Privkey(m_secret, 0, true);
    m_secret = Privkey(m_secret, 0, false);
    m_secret = Privkey(m_secret, NODE_BIP32_ACCOUNT_NBR, false);
}

EthNode &EthNode::GetInstance()
{
    if (m_sInstancePtr == NULL)
    {
        m_sInstancePtr = new EthNode();
        Ethnode.registerIdentity();
    }

    return *m_sInstancePtr;
}

EthNode *EthNode::m_sInstancePtr = NULL;

//--------------------------------------------------------------------------------

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
#include <p2p/EthSessionManager.h>

#include <Common.h>
#include <p2p/Messaging.h>

#define PORT 40404

int main(int argc , char *argv[])  
{
    // Initialize logging server endpoint and
    // register with the Initiation_Dispatcher.

    EthNode::GetInstance().startServer(PORT, IPPROTO_UDP);
    EthNode::GetInstance().startServer(PORT, IPPROTO_TCP);

    //if( shared_ptr<EthSessionManager> tcp = make_shared<EthSessionManager>(PORT, IPPROTO_TCP) )
    //    tcp->start();
    //if( shared_ptr<EthSessionManager> udp = make_shared<EthSessionManager>(node, PORT, IPPROTO_UDP) )
    //    udp->start();

    // Main event loop that handles client
    // logging records and connection requests.
    while(true)
        Initiation_Dispatcher::GetInstance().handle_events();
         
    return 0;  
}  
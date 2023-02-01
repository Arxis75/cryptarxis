#include <p2p/Node.h>
#include <p2p/DiscV4.h>

#include <Common.h>

/*#define NODE_TCP_PORT 40404
#define NODE_UDP_PORT 40404
#define NODE_IP 0x51430B52      //81.67.11.82
#define NODE_SECRET "0x4bbede0846299a5893929f9ebbadcd93933b91c8f4d1f7fe8d7f485c9b168815"    //some random privkey
*/

#define NODE_TCP_PORT 30303
#define NODE_UDP_PORT 30303
#define NODE_IP 0x7F000001      //127.0.0.1
#define NODE_SECRET "0xb71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291"

int main(int argc , char *argv[])  
{
    ENRV4Identity enr(NODE_IP, NODE_TCP_PORT, NODE_UDP_PORT, NODE_SECRET);

    DiscV4SessionManager udp_server(enr);
    udp_server.start();
    DiscV4SessionManager tcp_server(enr);
    tcp_server.start();


    // Initialize logging server endpoint and
    // register with the Initiation_Dispatcher.
    //EthNode::GetInstance(enr).startServer(IPPROTO_UDP);
    //EthNode::GetInstance(enr).startServer(IPPROTO_TCP);

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
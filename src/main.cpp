#include <reactor/InitiationDispatcher.h>
#include <reactor/SocketHandler.h>

#include <crypto/bips.h>
#include <tools/tools.h>

using std::cout;
using std::hex;
using std::dec;
using std::endl;

#define PORT 40404

int main(int argc , char *argv[])  
{
    // Initialize logging server endpoint and
    // register with the Initiation_Dispatcher.

    if( shared_ptr<SessionManager> tcp = make_shared<SessionManager>(PORT, IPPROTO_TCP) )
        tcp->start();
    if( shared_ptr<SessionManager> udp = make_shared<SessionManager>(PORT, IPPROTO_UDP) )
        udp->start();

    // Main event loop that handles client
    // logging records and connection requests.
    while(true)
        Initiation_Dispatcher::GetInstance().handle_events();
         
    return 0;  
}  

#include <p2p/Network.h>
#include "Common.h"

#define NODE_IP 0x51430B52      //81.67.11.82
#define NODE_UDP_PORT 40404
#define NODE_TCP_PORT 40404
#define NODE_SECRET "0x4bbede0846299a5893929f9ebbadcd93933b91c8f4d1f7fe8d7f485c9b168815"    //some random privkey

/* ENR TEST VECTOR
#define NODE_TCP_PORT 30303
#define NODE_UDP_PORT 30303
#define NODE_IP 0x7F000001      //127.0.0.1
#define NODE_SECRET "0xb71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291"
*/

int main(int argc , char *argv[])  
{   
    RLPByteStream node_i;
    uint64_t x = 0;
    //ByteStream y = ByteStream(x);
    uint8_t y = sizeInBytes64(x);

    Network::GetInstance().start(NODE_IP, NODE_UDP_PORT, NODE_TCP_PORT, NODE_SECRET);

    return 0;  
}  
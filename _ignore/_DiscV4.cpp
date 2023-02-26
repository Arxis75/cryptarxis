#include "_DiscV4.h"

using std::cout;
using std::hex;
using std::dec;
using std::endl;

DiscV4Session::DiscV4Session(const std::weak_ptr<const SocketHandler> socket_handler, const sockaddr_in &peer_address)
    : m_peer_enr(peer_address.sin_addr.s_addr, peer_address.sin_port, IPPROTO_UDP)
    , m_socket_handler(socket_handler)
{}

void DiscV4Session::onNewMessage(const shared_ptr<const DiscV4Message> msg_in)
{
    try
    {
        /*if(msg_in)
        {
            if( auto sh_in = msg_in->getSocketHandler() )
                cout << dec << "@ " << (sh_in->getProtocol() == IPPROTO_TCP ? "TCP" : "UDP") << " socket = " << sh_in->getSocket()
                        << " => @" << inet_ntoa(msg_in->getPeerAddress().sin_addr) << ":" << ntohs(msg_in->getPeerAddress().sin_port)
                        << ", " << msg_in->payload_vector().size() << " Bytes received" << endl;
        }

        //Worker job:
        auto msg_out = msg_in; //echo server here for example
        if(msg_out)
        {   
            
            RLPByteStream rlp(&msg_out->payload_vector()[0], msg_out->payload_vector().size());

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

            ByteStream msg_out_id = rlp.ByteStream::pop_front(1);
            cout << hex << msg_out_id << endl;
            
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
            if( auto sh_out = msg_out->getSocketHandler() )
                if( auto sm_out = sh_out->getSessionManager() )
                    const_pointer_cast<SocketHandler>(sh_out)->sendMsg(msg_out);    //test echo
        }*/
    }
    catch(const std::exception& e)
    {
        //TODO: CLOSE THE CONNECTION!

        std::cerr << "Invalid DiscV4 msg received from " << m_peer_enr.getIP() << ":" << m_peer_enr.getUDPPort() << endl;
    }
}

//-------------------------------------------------------------------------------------------------------

DiscV4SessionManager::DiscV4SessionManager(const ENRV4Identity &host_enr)
    : SessionManager()
    , m_host_enr(host_enr)
{ }

void DiscV4SessionManager::onNewMessage(const shared_ptr<const SocketMessage> msg_in)
{
    shared_ptr<DiscV4Session> peer_session = shared_ptr<DiscV4Session>(nullptr);
    
    uint64_t peer_key = (msg_in->getPeerAddress().sin_addr.s_addr << 16) + msg_in->getPeerAddress().sin_port;
    
    auto it = m_peer_session_list.find(peer_key);
    if( it != m_peer_session_list.end() )
        peer_session = it->second;
    else
        peer_session = make_shared<DiscV4Session>(msg_in->getSocketHandler(), msg_in->getPeerAddress());

    peer_session->onNewMessage(make_shared<DiscV4Message>(ByteStream(&msg_in->payload_vector()[0], msg_in->payload_vector().size()), peer_session));
}

//---------------------------------------------------------------------------------------------------------------

//Ingress constructor
DiscV4Message::DiscV4Message(const ByteStream msg, const shared_ptr<DiscV4Session> peer_session)
{
    if( msg && msg.byteSize() > 97)
    {
        m_msg = RLPByteStream(msg[0], msg.byteSize());
        if( !has_valid_hash() )
            throw std::invalid_argument("Invalid DiscV4 message hash!");
        
        m_type = m_msg[97];
        if(m_type > 0x06)
            throw std::invalid_argument("Invalid DiscV4 message type!");

        if( peer_session )
        {
            Pubkey key(peer_session->getPeerENR().getPubKey());
            if( !key.getKey(Pubkey::Format::XY).byteSize() )
            {
                // new pubkey, will be registered with the functionalMsg sent to the Session
            }
            else if( !has_valid_signature(peer_session->getPeerENR().getPubKey()) )
                //If this peer had already registered a different pubkey, throws
                throw std::invalid_argument("Invalid DiscV4 message signature!");
        }
    }
    else
        throw std::invalid_argument("Invalid DiscV4 message size!");
}

//Egress constructor
DiscV4Message::DiscV4Message(const uint8_t type)
    : m_type(type)
{ }

ByteStream DiscV4Message::serialize(const Privkey &secret, const RLPByteStream &rlp_payload) const
{
    if( m_msg.byteSize() )
        return m_msg;
    else
    {
        RLPByteStream msg = rlp_payload;
        msg.ByteStream::push_front(m_type, 1); //no RLP-encoding for the type
        Signature sig = secret.sign(msg.keccak256());
        msg.ByteStream::push_front(sig.get_imparity());
        msg.ByteStream::push_front(ByteStream(sig.get_s(), 32));
        msg.ByteStream::push_front(ByteStream(sig.get_r(), 32));
        msg.ByteStream::push_front(msg.keccak256());
        return msg;
    }
}

uint8_t DiscV4Message::getPacketType() const
{
    return (m_msg.byteSize() > 97 ? m_msg[97] : 0);
}

bool DiscV4Message::has_valid_hash() const
{
    return (m_msg.byteSize() > 32 ? ByteStream(m_msg[0], 32) == ByteStream(m_msg[32], m_msg.byteSize() - 32).keccak256() : false); 
}

bool DiscV4Message::has_valid_signature(Pubkey expected_pubkey) const
{
    Pubkey actual_pubkey;
    return getPublicKey(actual_pubkey) && actual_pubkey == expected_pubkey;
}

bool DiscV4Message::getPublicKey(Pubkey &key) const
{
    if(m_msg.byteSize() > 96)
    {
        Signature sig(ByteStream(m_msg[32], 32), ByteStream(m_msg[64], 32), ByteStream(m_msg[96], 1));
        return sig.ecrecover(key, ByteStream(m_msg[32], m_msg.byteSize() - 32).keccak256());
    }
    else
        return false;
}
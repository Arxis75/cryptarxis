#pragma once

#include <Common.h>
#include <crypto/bips.h>
#include <reactor/SocketHandler.h>
#include <vector>

using std::vector;

class DiscV4SignedMessage: public SocketMessage
{
    public:
        //Copy Constructor
        DiscV4SignedMessage(const shared_ptr<const DiscV4SignedMessage> signed_msg);
        //Constructor for building msg to send
        DiscV4SignedMessage(const shared_ptr<const SessionHandler> session_handler);

        void addTypeSignAndHash(const RLPByteStream &rlp_payload);

        inline const uint64_t getTimeStamp() const { return m_timestamp; }
        const ByteStream getHash() const;
        const Pubkey getPubKey() const;
        virtual const uint8_t getType() const;
        const RLPByteStream getRLPPayload() const;

        bool hasValidSize() const;
        bool hasValidHash() const;
        bool hasValidType(uint8_t &type) const;

        virtual uint64_t size() const;

        virtual operator const uint8_t*() const;

        virtual void push_back(const uint8_t value);
    
    protected:
        // Type + RLPPayload
        const ByteStream getSignedPayload() const;

    private:
        uint64_t m_timestamp;
        vector<uint8_t> m_vect;
};

class DiscV4PingMessage : public DiscV4SignedMessage
{
    public:
        //Constructor for received msg
        DiscV4PingMessage(const shared_ptr<const DiscV4SignedMessage> signed_msg);
        //Constructor for building msg to send
        DiscV4PingMessage(const shared_ptr<const SessionHandler> session_handler);

        inline bool hasValidVersion() const { return m_version == 4; }
        inline bool hasNotExpired() const { return m_expiration > getTimeStamp(); }

        inline virtual const uint8_t getType() const {return 0x01; }

        inline uint8_t getVersion() const { return m_version; }
        inline uint32_t getSenderIP() const { return m_sender_ip; }
        inline uint16_t getSenderUDPPort() const { return m_sender_udp_port; }
        inline uint16_t getSenderTCPPort() const { return m_sender_tcp_port; }
        inline uint32_t getRecipientIP() const { return m_recipient_ip; }
        inline uint16_t getRecipientUDPPort() const { return m_recipient_udp_port; }
        inline uint16_t getRecipientTCPPort() const { return m_recipient_tcp_port; }
        inline uint64_t getExpiration() const { return m_expiration; }
        inline uint64_t getENRSeq() const { return m_enr_seq; }

        void print() const;

    private:
        uint8_t m_version;
        uint32_t m_sender_ip;
        uint16_t m_sender_udp_port; 
        uint16_t m_sender_tcp_port; 
        uint32_t m_recipient_ip;
        uint16_t m_recipient_udp_port; 
        uint16_t m_recipient_tcp_port; 
        uint64_t m_expiration;
        uint64_t m_enr_seq;
};

class DiscV4PongMessage : public DiscV4SignedMessage
{
    public:
        //Constructor for received msg
        DiscV4PongMessage(const shared_ptr<const DiscV4SignedMessage> signed_msg);
        //Constructor for building msg to send
        DiscV4PongMessage(const shared_ptr<const SessionHandler> session_handlerc, const ByteStream &ack_hash);

        inline virtual const uint8_t getType() const {return 0x02; }

        inline bool hasValidPingHash(const ByteStream ping_hash) const { return ping_hash == getPingHash(); };
        inline bool hasNotExpired() const { return m_expiration > getTimeStamp(); }

        inline const ByteStream &getPingHash() const { return m_ping_hash; }
        inline uint32_t getRecipientIP() const { return m_recipient_ip; }
        inline uint16_t getRecipientUDPPort() const { return m_recipient_udp_port; }
        inline uint16_t getRecipientTCPPort() const { return m_recipient_tcp_port; }
        inline uint64_t getExpiration() const { return m_expiration; }
        inline uint64_t getENRSeq() const { return m_enr_seq; }

        void print() const;

    private:
        ByteStream m_ping_hash;
        uint32_t m_recipient_ip;
        uint16_t m_recipient_udp_port; 
        uint16_t m_recipient_tcp_port; 
        uint64_t m_expiration;
        uint64_t m_enr_seq;
};

class DiscV4FindNodeMessage : public DiscV4SignedMessage
{
    public:
        //Constructor for received msg
        DiscV4FindNodeMessage(const shared_ptr<const DiscV4SignedMessage> signed_msg);
        //Constructor for building msg to send
        DiscV4FindNodeMessage(const shared_ptr<const SessionHandler> session_handler, const Pubkey &pub_key);

        inline virtual const uint8_t getType() const {return 0x03; }
        inline const Pubkey &getTarget() const { return m_target; }

        inline bool hasNotExpired() const { return m_expiration > getUnixTimeStamp(); }

        void print() const;

    private:
        Pubkey m_target;
        uint64_t m_expiration;
};

class DiscV4NeighborsMessage : public DiscV4SignedMessage
{
    public:
        //Constructor for received msg
        DiscV4NeighborsMessage(const shared_ptr<const DiscV4SignedMessage> signed_msg);
        //Constructor for building msg to send
        DiscV4NeighborsMessage(const shared_ptr<const SessionHandler> session_handler, const vector<std::weak_ptr<const ENRV4Identity>> &neighbors_enr);

        inline virtual const uint8_t getType() const {return 0x04; }
        inline const vector<std::shared_ptr<const ENRV4Identity>> &getNodes() const { return m_nodes; }

        inline bool hasNotExpired() const { return m_expiration > getUnixTimeStamp(); }

        void print() const;

    private:
        vector<std::shared_ptr<const ENRV4Identity>> m_nodes;
        uint64_t m_expiration;
};

class DiscV4ENRRequestMessage : public DiscV4SignedMessage
{
    public:
        //Constructor for received msg
        DiscV4ENRRequestMessage(const shared_ptr<const DiscV4SignedMessage> signed_msg);
        //Constructor for building msg to send
        DiscV4ENRRequestMessage(const shared_ptr<const SessionHandler> session_handler);

        inline virtual const uint8_t getType() const {return 0x05; }

        inline bool hasNotExpired() const { return m_expiration > getUnixTimeStamp(); }

        void print() const;

    private:
        uint64_t m_expiration;
};

class ENRV4Identity;

class DiscV4ENRResponseMessage : public DiscV4SignedMessage
{
    public:
        //Constructor for received msg
        DiscV4ENRResponseMessage(const shared_ptr<const DiscV4SignedMessage> signed_msg);
        DiscV4ENRResponseMessage(const shared_ptr<const SessionHandler> session_handler, const ByteStream &ack_hash);

        inline virtual const uint8_t getType() const {return 0x06; }

        inline bool hasValidENRRequestHash(const ByteStream &enr_request_hash) const { return enr_request_hash == m_enr_request_hash; }

        inline const ByteStream &getENRRequestHash() const { return m_enr_request_hash; }
        inline const shared_ptr<const ENRV4Identity> getPeerENR() const { return m_sender_enr; }

        const shared_ptr<const DiscV4ENRResponseMessage> buildFromPingMessage(const shared_ptr<const DiscV4PingMessage> msg) const;
        const shared_ptr<const DiscV4ENRResponseMessage> buildFromPongMessage(const shared_ptr<const DiscV4PongMessage> msg) const ;

        void print() const;

    private:
        ByteStream m_enr_request_hash;
        shared_ptr<const ENRV4Identity> m_sender_enr;
};
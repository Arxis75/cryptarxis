#pragma once

#include <p2p/Discovery.h>

#include <crypto/bips.h>
#include <Common.h>
#include <vector>
#include <string>

using std::vector;

class DiscV4SignedMessage: public DiscoveryMessage
{
    public:
        //Copy Constructor
        DiscV4SignedMessage(const shared_ptr<const DiscV4SignedMessage> signed_msg);
        //Raw msg constructor
        DiscV4SignedMessage(const vector<uint8_t> &buffer);
        //session-embedded empty msg
        DiscV4SignedMessage(const shared_ptr<const SessionHandler> session_handler);

        void addTypeSignAndHash(const RLPByteStream &rlp_payload);

        inline const ByteStream &getHash() const { return m_hash; }
        inline const Pubkey &getPubKey() const { return m_pub_key; }
        inline const string getName() const;
        virtual inline const vector<uint8_t> getPeerID() const { return (const vector<uint8_t>)m_ID; };
        // isSessionBootstrapper filters non-ping messages from a same IP:Port with changing ID.
        // => It forces the peer to resend a ping publishing its new ID
        virtual inline bool isSessionBootstrapper() const { return getType() == 0x01; }

        inline bool hasValidSize() const { return size() > 98; }
        inline bool hasValidHash() const { return getHash() == getHashedPayload().keccak256(); }
       
        virtual inline bool isValid() const { return hasValidSize() && hasValidHash() && getType() && getType() < 7; }
        virtual inline const uint8_t getType() const { return m_type; }
        virtual void print() const;

    protected:
        // Signature || Type || RLP
        inline const ByteStream &getHashedPayload() const { return m_hashed_payload; }
        // Type || RLP
        inline const ByteStream &getSignedPayload() const { return m_signed_payload; }
        // RLP
        inline const RLPByteStream &getRLPPayload() const { return m_rlp_payload; }

    private:
        ByteStream m_hash;
        Pubkey m_pub_key;
        ByteStream m_hashed_payload;
        ByteStream m_signed_payload;
        ByteStream m_ID;
        uint8_t m_type;
        RLPByteStream m_rlp_payload;
};

class DiscV4PingMessage : public DiscV4SignedMessage
{
    public:
        //Copy Constructor
        DiscV4PingMessage(const shared_ptr<const DiscV4SignedMessage> signed_msg);
        //Constructor for building msg to send
        DiscV4PingMessage(const shared_ptr<const SessionHandler> session_handler);

        inline bool hasValidVersion() const { return m_version == 4; }
        inline bool hasNotExpired() const { return m_expiration > getTimeStamp(); }

        virtual inline const uint8_t getType() const {return 0x01; }

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
        //Copy Constructor
        DiscV4PongMessage(const shared_ptr<const DiscV4SignedMessage> signed_msg);
        //Constructor for building msg to send
        DiscV4PongMessage(const shared_ptr<const SessionHandler> session_handler, const ByteStream &ack_hash);

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
        //Copy Constructor
        DiscV4FindNodeMessage(const shared_ptr<const DiscV4SignedMessage> signed_msg);
        //Constructor for building msg to send
        DiscV4FindNodeMessage(const shared_ptr<const SessionHandler> session_handler);

        inline virtual const uint8_t getType() const {return 0x03; }

        inline const Pubkey &getTarget() const { return m_target; }
        inline const ByteStream getTargetID() const { return getTarget().getKey(Pubkey::Format::XY).keccak256(); }

        inline bool hasNotExpired() const { return m_expiration > getUnixTimeStamp(); }

        void print() const;

    private:
        Pubkey m_target;
        uint64_t m_expiration;
};

class DiscV4NeighborsMessage : public DiscV4SignedMessage
{
    public:
        //Copy Constructor
        DiscV4NeighborsMessage(const shared_ptr<const DiscV4SignedMessage> signed_msg);
        //Constructor for building msg to send
        DiscV4NeighborsMessage(const shared_ptr<const SessionHandler> session_handler, const vector<shared_ptr<const ENRV4Identity>> &neighbors_enr);

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
        //Copy Constructor
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
        //Copy Constructor
        DiscV4ENRResponseMessage(const shared_ptr<const DiscV4SignedMessage> signed_msg);
        //Constructor for building msg to send
        DiscV4ENRResponseMessage(const shared_ptr<const SessionHandler> session_handler, const ByteStream &ack_hash);

        inline virtual const uint8_t getType() const {return 0x06; }

        inline bool hasValidENRRequestHash(const ByteStream &enr_request_hash) const { return enr_request_hash == m_enr_request_hash; }

        inline const ByteStream &getENRRequestHash() const { return m_enr_request_hash; }
        inline const shared_ptr<const ENRV4Identity> getENR() const { return m_sender_enr; }

        void print() const;

    private:
        ByteStream m_enr_request_hash;
        shared_ptr<const ENRV4Identity> m_sender_enr;
};
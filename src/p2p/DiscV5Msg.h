#pragma once

#include "Discovery.h"

#include <Common.h>
#include <crypto/bips.h>
#include <reactor/SocketHandler.h>
#include <vector>

using std::vector;

class DiscV5UnauthMessage: public DiscoveryMessage
{
    public:
        enum class Flag{UKNOWN = -1, ORDINARY = 0, WHOAREYOU = 1, HANDSHAKE = 2};

        //Copy Constructor
        DiscV5UnauthMessage(const shared_ptr<const DiscV5UnauthMessage> unmasked_header_msg);
        //Raw msg constructor
        DiscV5UnauthMessage(const shared_ptr<const SocketHandler> handler, const vector<uint8_t> buffer, const struct sockaddr_in &peer_addr, const bool is_ingress = true);
        //session-embedded empty msg
        DiscV5UnauthMessage(const shared_ptr<const SessionHandler> session_handler);

        const ByteStream &getMaskingIV() const { return m_masking_iv; }
        const ByteStream &getMaskedHeader() const { return m_masked_header; }
        const ByteStream &getProtocol() const { return m_protocol_id; }
        uint16_t getVersion() const { return m_version; }
        Flag getFlag() const { return m_flag; }
        const ByteStream &getNonce() const { return m_nonce; }
        uint16_t getAuthDataSize() const { return m_authdata_size; }
        const ByteStream &getAuthData() const { return m_authdata; }
        virtual const ByteStream &getMessageData() const { return m_message_data; }

        const ByteStream getHeader() const;

        inline bool hasValidSize() const { return getFlag() == Flag::WHOAREYOU ? size() == 63 : size() > 63 && size() <= 1280; }
        inline bool hasValidProtocol() const { return getProtocol() == ByteStream("discv5"); }
        inline bool hasValidVersion() const { return getVersion() == 0x0001; }
        inline bool hasValidFlag() const { return getFlag() == Flag::ORDINARY ||  getFlag() == Flag::WHOAREYOU || getFlag() == Flag::HANDSHAKE; }
        
        virtual inline bool isValid() const { return hasValidSize() && hasValidProtocol() && hasValidVersion() && hasValidFlag(); }

        const string getName() const;
        virtual void print() const;

    protected:
        virtual void encryptMessage();
     
    private:
        ByteStream m_masking_iv;        // 16 bytes
        ByteStream m_masked_header;
        ByteStream m_protocol_id;       // 6 bytes
        uint16_t m_version;             // 2 bytes
    protected:
        Flag m_flag;                    // 1 byte
        ByteStream m_nonce;             // 12 bytes
        uint16_t m_authdata_size;       // 2 bytes
        ByteStream m_authdata;          // m_authdata_size bytes
        ByteStream m_message_data;
};

class DiscV5WhoAreYouMessage: public DiscV5UnauthMessage
{
    public:
        //Copy Constructor
        DiscV5WhoAreYouMessage(const shared_ptr<const DiscV5WhoAreYouMessage> way_msg);
        //Parsing Constructor
        DiscV5WhoAreYouMessage(const shared_ptr<const DiscV5UnauthMessage> masked_header);
        //session-embedded empty msg
        DiscV5WhoAreYouMessage(const shared_ptr<const SessionHandler> session_handler, const ByteStream &request_nonce);

        const ByteStream getChallengeData() const;
        const ByteStream &getIDNonce() const { return m_id_nonce; }
        uint64_t getENRSeq() const { return m_enr_seq; }

        virtual void print() const;

    protected:
        virtual void encryptMessage();

    private:
        ByteStream m_id_nonce;          // 16 bytes
        uint64_t m_enr_seq;             // 8 bytes
};

class DiscV5AuthMessage: public DiscV5UnauthMessage
{
    public:
        //Copy Constructor
        DiscV5AuthMessage(const shared_ptr<const DiscV5AuthMessage> unmasked_msg, bool add_hanshake_header = false);
        //Parsing Constructor
        DiscV5AuthMessage(const shared_ptr<const DiscV5UnauthMessage> unmasked_header_msg);
        //session-embedded empty msg
        DiscV5AuthMessage(const shared_ptr<const SessionHandler> session_handler, const Flag flag, const uint8_t type);

        inline const ByteStream &getSourceID() const { return m_src_ID; }
        inline uint8_t getIDSignatureSize() const { return m_id_sig_size; }
        inline uint8_t getEphemeralPubKeySize() const { return m_eph_pub_key_size; }
        inline const ByteStream &getIDSignature() const { return m_id_sig; }
        inline const Pubkey &getEphemeralPubKey() const { return m_eph_pub_key; }
        inline shared_ptr<const ENRV4Identity> getENR() const { return m_enr; }
        inline uint8_t getType() const { return m_type; }
        inline const RLPByteStream &getRLPPayload() const { return m_rlp_payload; }

        const string getName() const;
        virtual void print() const;

    protected:
        void addHandshakeHeader();
        void generateHandshakeKeys(ByteStream &IDSignature, Pubkey &ephemeral_pubkey);
        void extractHandshakeKeys();

        virtual void encryptMessage();

    private:
        // the peer ID is parsed here, but stored as m_peer_ID in SocketMessage class
        // as it is used as key to associate to a session
        ByteStream m_src_ID;
        uint8_t m_id_sig_size;
        uint8_t m_eph_pub_key_size;
        ByteStream m_id_sig;
        Pubkey m_eph_pub_key;
        shared_ptr<const ENRV4Identity> m_enr;
        uint8_t m_type;
    protected:
        RLPByteStream m_rlp_payload;
};

class DiscV5PingMessage : public DiscV5AuthMessage
{
    public:
        //Parsing Constructor
        DiscV5PingMessage(const shared_ptr<const DiscV5AuthMessage> unmasked_msg);
        //Constructor for building msg to send
        DiscV5PingMessage(const shared_ptr<const SessionHandler> session_handler, const Flag flag, const uint64_t request_id);

        inline uint64_t getRequestID() const { return m_request_id; }
        inline uint64_t getENRSeq() const { return m_enr_seq; }

        virtual void print() const;

    private:
        uint64_t m_request_id;
        uint64_t m_enr_seq;
};

class DiscV5PongMessage : public DiscV5AuthMessage
{
    public:
        //Parsing Constructor
        DiscV5PongMessage(const shared_ptr<const DiscV5AuthMessage> unmasked_msg);
        //Constructor for building msg to send
        DiscV5PongMessage(const shared_ptr<const SessionHandler> session_handler, const Flag flag, const uint64_t request_id);

        inline uint64_t getRequestID() const { return m_request_id; }
        inline uint64_t getENRSeq() const { return m_enr_seq; }
        inline uint32_t getRecipientIP() const { return m_recipient_ip; }
        inline uint16_t getRecipientUDPPort() const { return m_recipient_udp_port; }

        virtual void print() const;

    private:
        uint64_t m_request_id;
        uint64_t m_enr_seq;
        uint32_t m_recipient_ip;
        uint16_t m_recipient_udp_port; 
};
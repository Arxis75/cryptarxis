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
        enum class Flag{ORDINARY = 0, WHOAREYOU = 1, HANDSHAKE = 2};

        //Copy Constructor
        DiscV5UnauthMessage(const shared_ptr<const DiscV5UnauthMessage> unmasked_header_msg);
        //Raw msg constructor
        DiscV5UnauthMessage(const shared_ptr<const SocketHandler> handler, const vector<uint8_t> buffer, const struct sockaddr_in &peer_addr, const bool is_ingress = true);
        //session-embedded empty msg
        DiscV5UnauthMessage(const shared_ptr<const SessionHandler> session_handler, const Flag flag, const ByteStream &request_nonce = ByteStream());

        const ByteStream &getMaskingIV() const { return m_masking_iv; }
        const ByteStream &getMaskedHeader() const { return m_masked_header; }
        const ByteStream &getProtocol() const { return m_protocol_id; }
        uint16_t getVersion() const { return m_version; }
        Flag getFlag() const { return m_flag; }
        const ByteStream &getNonce() const { return m_nonce; }
        uint16_t getAuthDataSize() const { return m_authdata_size; }
        const ByteStream &getHeader() const { return m_header; }
        const ByteStream &getMessageData() const { return m_message_data; }

        virtual inline bool hasValidSize() const { return getFlag() == Flag::WHOAREYOU ? size() == 63 : size() > 63 && size() <= 1280; }
        inline bool hasValidProtocol() const { return getProtocol() == ByteStream("discv5"); }
        inline bool hasValidVersion() const { return getVersion() == 0x0001; }
        inline bool hasValidFlag() const { return getFlag() == Flag::ORDINARY ||  getFlag() == Flag::WHOAREYOU || getFlag() == Flag::HANDSHAKE; }
        
        virtual inline bool isValid() const { return hasValidSize() && hasValidProtocol() && hasValidVersion() && hasValidFlag(); }

    protected:
        void encryptHeader();
        virtual void encryptData() {};
        void encryptMessage();

    private:
        ByteStream m_masking_iv;        // 16 bytes
        ByteStream m_masked_header;
        ByteStream m_protocol_id;       // 6 bytes
        uint16_t m_version;             // 2 bytes
        Flag m_flag;                    // 1 byte
        ByteStream m_nonce;             // 12 bytes
        uint16_t m_authdata_size;       // 2 bytes
    protected:
        ByteStream m_header;            // 23 + m_authdata_size bytes
        ByteStream m_message_data;      // encrypted(Type + RLP)
};

class DiscV5WhoAreYouMessage: public DiscV5UnauthMessage
{
    public:
        //Parsing Constructor
        DiscV5WhoAreYouMessage(const shared_ptr<const DiscV5UnauthMessage> masked_header);
        //session-embedded empty msg
        DiscV5WhoAreYouMessage(const shared_ptr<const SessionHandler> session_handler, const ByteStream &request_nonce);

        const ByteStream getChallengeData() const;
        const ByteStream &getIDNonce() const { return m_id_nonce; }
        uint64_t getENRSeq() const { return m_enr_seq; }

        virtual inline bool hasValidSize() const { return size() == 63; }

    private:
        ByteStream m_id_nonce;          // 16 bytes
        uint64_t m_enr_seq;             // 8 bytes
};

class DiscV5AuthMessage: public DiscV5UnauthMessage
{
    public:
        //Copy Constructor
        DiscV5AuthMessage(const shared_ptr<const DiscV5AuthMessage> unmasked_msg);
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

    protected:
        void generateHandshakeKeys(ByteStream &IDSignature, Pubkey &ephemeral_pubkey);
        void extractHandshakeKeys();

        virtual void encryptData();

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

    private:
        uint64_t m_request_id;
        uint64_t m_enr_seq;
};

/*
        // Raw Ingress Message from Socket: shall be handled by the session to make a new message
        // by calling the copy-constructor with the peer session key to decrypt the message data
        DiscV5AuthMessage( const shared_ptr<const SessionHandler> session_handler );

        // Copy Constructor
        DiscV5AuthMessage(const shared_ptr<const DiscV5AuthMessage> masked_msg);
        
        // Constructor for building "whoareyou" msg to send:
        // - dest_node_id is the peer ID (pubkey keccak256) that sent the unreadble message (was src-id field in that msg)
        // - mirroring_nonce is the nonce of the unreadble message that triggered a "whoareyou" response
        // - challenge_data is returned by the constructor to be stored in the session
        // - enr_seq represents previous knownledge of peer's ent seq 
        DiscV5AuthMessage(const shared_ptr<const SessionHandler> session_handler, 
                            const ByteStream &dest_node_id, const ByteStream &mirroring_nonce, 
                            ByteStream &challenge_data,
                            uint64_t enr_seq = 0);
        
        // Constructor for building "ordinary"/"handshake" msg to send
        DiscV5AuthMessage( const shared_ptr<const SessionHandler> session_handler, 
                             uint32_t &session_egress_msg_counter, const Flag flag,
                             const ByteStream &host_session_key,
                             const ByteStream &IDSignature = ByteStream(), const ByteStream &ephemeral_pubkey = ByteStream());

        const bool hasValidSize() const { return m_vect.size() >= 63; }
        const bool hasValidProtocolID() const { return getProtocolID() == "discv5"; }
        const bool hasValidVersion() const { return getVersion() == 0x0001; }

        const ByteStream getMaskingKey() const;
        const ByteStream getMaskingIV() const;
        const ByteStream getMaskedHeader() const;
        const ByteStream getHeader(uint8_t ofs = 0, uint8_t size = 0) const;
        const ByteStream getChallengeData() const;
        int generateHandshakeKeys( const Pubkey &peer_pub_key, 
                                   ByteStream &ephemeral_pubkey,
                                   ByteStream &host_session_key, ByteStream &peer_session_key, 
                                   ByteStream &IDSignature ) const;

        int extractSessionKeys(ByteStream &initiator_key, ByteStream &recipient_key) const;

        const string getProtocolID() const { return string(getHeader(0, 6)); }
        const uint16_t getVersion() const { return getHeader(6, 2).as_uint64(); }
        const Flag getFlag() const { return (Flag)getHeader(8, 1).as_uint8(); }
        const ByteStream getNonce() const { return getHeader(9, 12); }
        const uint16_t getAuthDataSize() const { return getHeader(21, 2).as_uint64(); }
        
        // ORDINARY or HANDSHAKE
        const ByteStream getSourceID() const { return getHeader(23, 32); }
        const ByteStream getMessageData() const;
        // WHOAREYOU
        const ByteStream getIDNonce() const { return getHeader(23, 16); }
        const ByteStream getENRSeq() const { return getHeader(39, 8); }
        // HANDSHAKE
        const uint8_t getIDSignatureSize() const { return getHeader(55, 1).as_uint8(); }
        const uint8_t getEphemeralPubKeySize() const { return getHeader(56, 1).as_uint8(); }
        const ByteStream getIDSignature() const { return getHeader(57, getIDSignatureSize()).as_uint8(); }
        const ByteStream getEphemeralPubKey() const { return getHeader(57 + getIDSignatureSize(), getEphemeralPubKeySize()).as_uint8(); }
        const shared_ptr<const ENRV4Identity> getENR() const;

        //Virtual methods
        virtual uint64_t size() const;
        virtual operator const uint8_t*() const;
        virtual void push_back(const uint8_t value);
    
    protected:
        // Type + RLPPayload
        const ByteStream getSignedPayload() const;
};*/
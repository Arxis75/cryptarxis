#pragma once

#include "Discovery.h"

#include <Common.h>
#include <crypto/bips.h>
#include <reactor/SocketHandler.h>
#include <vector>

using std::vector;

class DiscV5AuthMessage: public DiscoveryMessage
{
    public:
        enum class Flag{ORDINARY = 0, WHOAREYOU = 1, HANDSHAKE = 2};

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
        //const ByteStream getChallengeData() const;
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

    private:
        uint64_t m_timestamp;
        bool m_is_ingress;
        vector<uint8_t> m_vect;
};
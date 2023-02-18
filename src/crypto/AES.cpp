# include "AES.h"

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>
#include <openssl/err.h>

#include <openssl/params.h>
#include <openssl/core_names.h>
#include <string.h>

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int gcm_encrypt(const unsigned char *plaintext, int plaintext_len,
                const unsigned char *aad, int aad_len,
                const unsigned char *key,
                const unsigned char *iv, int iv_len,
                unsigned char *ciphertext,
                unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;


    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
        handleErrors();

    /*
     * Set IV length if default 12 bytes (96 bits) is not appropriate
     */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrors();

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors();

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
        handleErrors();

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int gcm_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                const unsigned char *aad, int aad_len,
                const unsigned char *tag,
                const unsigned char *key,
                const unsigned char *iv, int iv_len,
                unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
        handleErrors();

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrors();

    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors();

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag))
        handleErrors();

    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0) {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    } else {
        /* Verify failed */
        return -1;
    }
}

int ctr_encrypt(const unsigned char *plaintext, int plaintext_len,
                const unsigned char *key,
                const unsigned char *iv, int iv_len,
                unsigned char *ciphertext)
{
   EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;


    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, NULL, NULL))
        handleErrors();

    /*
     * Set IV length if default 12 bytes (96 bits) is not appropriate
     */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrors();

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int ctr_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                const unsigned char *key,
                const unsigned char *iv, int iv_len,
                unsigned char *plaintext)
{
    return ctr_encrypt(ciphertext, ciphertext_len, key, iv, iv_len, plaintext);
}

int hkdf_derive(const unsigned char *key, int key_len,
                const unsigned char *salt, int salt_len,
                const unsigned char *info, int info_len,
                unsigned char *new_key)
{
    int retval = -1;
    EVP_KDF *kdf = 0;
    EVP_KDF_CTX *kctx = 0;
    unsigned char key_data[32];
    OSSL_PARAM params[5], *p = params;

    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);

    if (kdf)
    {
        kctx = EVP_KDF_CTX_new(kdf);

        EVP_KDF_free(kdf);

        if (kctx)
        {
            memset(params, 0, sizeof(params));
            memset(key_data, 0, sizeof(key_data));

            *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, SN_sha256, 0);
            *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (unsigned char*)key, key_len);
            *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (unsigned char*)salt, salt_len);
            *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (unsigned char*)info, info_len);
            *p = OSSL_PARAM_construct_end();

            retval = EVP_KDF_derive(kctx, key_data, sizeof(key_data), params);

            if( retval > 0)
                memcpy(new_key, &key_data[0], 32);

            EVP_KDF_CTX_free(kctx);
        }
    }
    return retval;
}

/*int HKDF_DERIVE(const Pubkey &peer_pub_key, const Privkey &ephemeral_key, const Pubkey &shared_secret, const ByteStream &challenge_data, )
{
    EVP_KDF *kdf = 0;
    EVP_KDF_CTX *kctx = 0;
    unsigned char key_data[32];
    OSSL_PARAM params[5], *p = params;

    Pubkey ecdh(Secp256k1::GetInstance().p_scalar(node_b_secret.getPubKey().getPoint(), ephemeral_key.getSecret()));
    ByteStream shared_secret = ecdh.getKey(Pubkey::Format::PREFIXED_X);

    ByteStream kdf_info("discovery v5 key agreement");
    kdf_info.push_back(node_id_a);
    kdf_info.push_back(node_id_b);

    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);

    if (kdf)
    {
        kctx = EVP_KDF_CTX_new(kdf);

        EVP_KDF_free(kdf);

        if (kctx)
        {
            const char *mdname = SN_sha256;

            memset(params, 0, sizeof(params));
            memset(key_data, 0, sizeof(key_data));

            *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, SN_sha256, 0);
            *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, shared_secret, shared_secret.byteSize());
            *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, challenge_data, challenge_data.byteSize());
            *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, kdf_info, kdf_info.byteSize());

            *p = OSSL_PARAM_construct_end();

            if (EVP_KDF_derive(kctx, key_data, sizeof(key_data), params) <= 0)
            {
                perror("EVP_KDF_derive Error!");
            }
            else

            ByteStream initiator_key(&key_data[0], 16);
            ByteStream recipient_key(&key_data[16], 16);

            std::cout << "initiator-key = 0x" << std::hex << initiator_key << std::endl;
            std::cout << "recipient-key = 0x" << std::hex << recipient_key << std::endl;

            EVP_KDF_CTX_free(kctx);
        }
    }
}*/
#pragma once

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/modes.h>
#include <openssl/kdf.h>

void handleErrors(void);

int ctr_encrypt(const unsigned char *plaintext, int plaintext_len,
                const unsigned char *key,
                const unsigned char *iv, int iv_len,
                unsigned char *ciphertext);

int ctr_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                const unsigned char *key,
                const unsigned char *iv, int iv_len,
                unsigned char *plaintext);

int gcm_encrypt(const unsigned char *plaintext, int plaintext_len,
                const unsigned char *aad, int aad_len,
                const unsigned char *key,
                const unsigned char *iv, int iv_len,
                unsigned char *ciphertext,
                unsigned char *tag);

int gcm_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                const unsigned char *aad, int aad_len,
                const unsigned char *tag,
                const unsigned char *key,
                const unsigned char *iv, int iv_len,
                unsigned char *plaintext);

int hkdf_derive(const unsigned char *key, int key_len,
                const unsigned char *salt, int salt_len,
                const unsigned char *info, int info_len,
                unsigned char *new_key);
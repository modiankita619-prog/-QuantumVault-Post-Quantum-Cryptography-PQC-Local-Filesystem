#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define KEY_LEN 32
#define NONCE_LEN 12
#define TAG_LEN 16

int main(void) {
    int result = EXIT_FAILURE;
    EVP_PKEY_CTX *kg = NULL, *enc = NULL, *dec = NULL;
    EVP_PKEY *kem_key = NULL;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    EVP_CIPHER_CTX *cipher = NULL;

    unsigned char *kem_ct = NULL;
    unsigned char *secret1 = NULL, *secret2 = NULL;
    size_t kem_ct_len = 0, secret1_len = 0, secret2_len = 0;

    unsigned char aes_key[KEY_LEN] = {0};
    unsigned char nonce[NONCE_LEN] = {0};
    unsigned char tag[TAG_LEN] = {0};

    const unsigned char plaintext[] =
        "QuantumVault integrated post-quantum encryption test";
    unsigned char encrypted[sizeof(plaintext) + 16] = {0};
    unsigned char decrypted[sizeof(plaintext) + 16] = {0};
    int out_len = 0, total_len = 0;

    kg = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL);
    if (!kg || EVP_PKEY_keygen_init(kg) <= 0 ||
        EVP_PKEY_generate(kg, &kem_key) <= 0) {
        fprintf(stderr, "ML-KEM key generation failed\n");
        goto cleanup;
    }

    enc = EVP_PKEY_CTX_new(kem_key, NULL);
    if (!enc || EVP_PKEY_encapsulate_init(enc, NULL) <= 0 ||
        EVP_PKEY_encapsulate(enc, NULL, &kem_ct_len,
                             NULL, &secret1_len) <= 0) {
        fprintf(stderr, "ML-KEM encapsulation setup failed\n");
        goto cleanup;
    }

    kem_ct = OPENSSL_malloc(kem_ct_len);
    secret1 = OPENSSL_malloc(secret1_len);
    if (!kem_ct || !secret1 ||
        EVP_PKEY_encapsulate(enc, kem_ct, &kem_ct_len,
                             secret1, &secret1_len) <= 0) {
        fprintf(stderr, "ML-KEM encapsulation failed\n");
        goto cleanup;
    }

    dec = EVP_PKEY_CTX_new(kem_key, NULL);
    if (!dec || EVP_PKEY_decapsulate_init(dec, NULL) <= 0 ||
        EVP_PKEY_decapsulate(dec, NULL, &secret2_len,
                             kem_ct, kem_ct_len) <= 0) {
        fprintf(stderr, "ML-KEM decapsulation setup failed\n");
        goto cleanup;
    }

    secret2 = OPENSSL_malloc(secret2_len);
    if (!secret2 ||
        EVP_PKEY_decapsulate(dec, secret2, &secret2_len,
                             kem_ct, kem_ct_len) <= 0 ||
        secret1_len != secret2_len ||
        CRYPTO_memcmp(secret1, secret2, secret1_len) != 0) {
        fprintf(stderr, "ML-KEM shared-secret verification failed\n");
        goto cleanup;
    }
    printf("ML-KEM-768 shared secret: SUCCESS\n");

    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) {
        fprintf(stderr, "HKDF unavailable\n");
        goto cleanup;
    }
    kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx) goto cleanup;

    char digest[] = "SHA256";
    char *properties = NULL;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0),
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_PROPERTIES, properties, 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, secret1, secret1_len),
        OSSL_PARAM_construct_end()
    };

    if (EVP_KDF_derive(kctx, aes_key, sizeof(aes_key), params) <= 0) {
        fprintf(stderr, "HKDF key derivation failed\n");
        goto cleanup;
    }
    printf("HKDF-SHA256 AES key derivation: SUCCESS\n");

    if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
        fprintf(stderr, "Nonce generation failed\n");
        goto cleanup;
    }

    cipher = EVP_CIPHER_CTX_new();
    if (!cipher ||
        EVP_EncryptInit_ex(cipher, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(cipher, EVP_CTRL_GCM_SET_IVLEN,
                            NONCE_LEN, NULL) != 1 ||
        EVP_EncryptInit_ex(cipher, NULL, NULL, aes_key, nonce) != 1 ||
        EVP_EncryptUpdate(cipher, encrypted, &out_len,
                          plaintext, sizeof(plaintext) - 1) != 1) {
        fprintf(stderr, "AES-GCM encryption failed\n");
        goto cleanup;
    }
    total_len = out_len;
    if (EVP_EncryptFinal_ex(cipher, encrypted + total_len, &out_len) != 1 ||
        EVP_CIPHER_CTX_ctrl(cipher, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1) {
        fprintf(stderr, "AES-GCM finalization failed\n");
        goto cleanup;
    }
    total_len += out_len;
    printf("AES-256-GCM encryption: SUCCESS\n");

    EVP_CIPHER_CTX_free(cipher);
    cipher = EVP_CIPHER_CTX_new();
    if (!cipher ||
        EVP_DecryptInit_ex(cipher, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(cipher, EVP_CTRL_GCM_SET_IVLEN,
                            NONCE_LEN, NULL) != 1 ||
        EVP_DecryptInit_ex(cipher, NULL, NULL, aes_key, nonce) != 1 ||
        EVP_DecryptUpdate(cipher, decrypted, &out_len,
                          encrypted, total_len) != 1) {
        fprintf(stderr, "AES-GCM decryption setup failed\n");
        goto cleanup;
    }
    total_len = out_len;
    if (EVP_CIPHER_CTX_ctrl(cipher, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag) != 1 ||
        EVP_DecryptFinal_ex(cipher, decrypted + total_len, &out_len) != 1) {
        fprintf(stderr, "AES-GCM authentication failed\n");
        goto cleanup;
    }
    total_len += out_len;
    decrypted[total_len] = '\0';

    if (strcmp((char *)plaintext, (char *)decrypted) != 0) {
        fprintf(stderr, "Decrypted text does not match\n");
        goto cleanup;
    }

    printf("AES-256-GCM authentication: SUCCESS\n");
    printf("Decrypted message: %s\n", decrypted);

    /* Tamper test: modified authentication tag must be rejected. */
    tag[0] ^= 0x01;
    EVP_CIPHER_CTX_free(cipher);
    cipher = EVP_CIPHER_CTX_new();

    if (!cipher ||
        EVP_DecryptInit_ex(cipher, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(cipher, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) != 1 ||
        EVP_DecryptInit_ex(cipher, NULL, NULL, aes_key, nonce) != 1 ||
        EVP_DecryptUpdate(cipher, decrypted, &out_len, encrypted, total_len) != 1) {
        fprintf(stderr, "Tamper test setup failed\n");
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(cipher, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag) != 1) {
        fprintf(stderr, "Tamper test tag setup failed\n");
        goto cleanup;
    }

    {
        int tamper_final_len = 0;
        if (EVP_DecryptFinal_ex(cipher, decrypted + out_len,
                                &tamper_final_len) == 1) {
            fprintf(stderr, "ERROR: Modified tag was accepted\n");
            goto cleanup;
        }
    }

    printf("AES-256-GCM tamper detection: SUCCESS (modified tag rejected)\n");

    result = EXIT_SUCCESS;

cleanup:
    if (result != EXIT_SUCCESS) ERR_print_errors_fp(stderr);
    OPENSSL_cleanse(aes_key, sizeof(aes_key));
    OPENSSL_cleanse(secret1, secret1_len);
    OPENSSL_cleanse(secret2, secret2_len);
    OPENSSL_cleanse(decrypted, sizeof(decrypted));
    OPENSSL_free(secret1);
    OPENSSL_free(secret2);
    OPENSSL_free(kem_ct);
    EVP_CIPHER_CTX_free(cipher);
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    EVP_PKEY_CTX_free(kg);
    EVP_PKEY_CTX_free(enc);
    EVP_PKEY_CTX_free(dec);
    EVP_PKEY_free(kem_key);
    return result;
}

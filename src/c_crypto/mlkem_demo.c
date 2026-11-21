#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>

int main(void) {
    EVP_PKEY_CTX *keygen_ctx = NULL;
    EVP_PKEY *keypair = NULL;
    EVP_PKEY_CTX *encap_ctx = NULL;
    EVP_PKEY_CTX *decap_ctx = NULL;

    unsigned char *public_key = NULL;
    unsigned char *private_key = NULL;
    unsigned char *ciphertext = NULL;
    unsigned char *secret_enc = NULL;
    unsigned char *secret_dec = NULL;

    size_t public_len = 0, private_len = 0;
    size_t ciphertext_len = 0;
    size_t secret_enc_len = 0, secret_dec_len = 0;

    int result = EXIT_FAILURE;

    keygen_ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL);

    if (!keygen_ctx || EVP_PKEY_keygen_init(keygen_ctx) <= 0 ||
        EVP_PKEY_generate(keygen_ctx, &keypair) <= 0) {
        fprintf(stderr, "ML-KEM-768 key generation failed.\n");
        goto cleanup;
    }

    if (EVP_PKEY_get_raw_public_key(keypair, NULL, &public_len) <= 0 ||
        EVP_PKEY_get_raw_private_key(keypair, NULL, &private_len) <= 0) {
        fprintf(stderr, "Key length retrieval failed.\n");
        goto cleanup;
    }

    public_key = malloc(public_len);
    private_key = malloc(private_len);

    if (!public_key || !private_key ||
        EVP_PKEY_get_raw_public_key(keypair, public_key, &public_len) <= 0 ||
        EVP_PKEY_get_raw_private_key(keypair, private_key, &private_len) <= 0) {
        fprintf(stderr, "Key export failed.\n");
        goto cleanup;
    }

    encap_ctx = EVP_PKEY_CTX_new(keypair, NULL);

    if (!encap_ctx || EVP_PKEY_encapsulate_init(encap_ctx, NULL) <= 0 ||
        EVP_PKEY_encapsulate(encap_ctx, NULL, &ciphertext_len,
                             NULL, &secret_enc_len) <= 0) {
        fprintf(stderr, "Encapsulation initialization failed.\n");
        goto cleanup;
    }

    ciphertext = malloc(ciphertext_len);
    secret_enc = malloc(secret_enc_len);

    if (!ciphertext || !secret_enc ||
        EVP_PKEY_encapsulate(encap_ctx, ciphertext, &ciphertext_len,
                             secret_enc, &secret_enc_len) <= 0) {
        fprintf(stderr, "Encapsulation failed.\n");
        goto cleanup;
    }

    decap_ctx = EVP_PKEY_CTX_new(keypair, NULL);

    if (!decap_ctx || EVP_PKEY_decapsulate_init(decap_ctx, NULL) <= 0 ||
        EVP_PKEY_decapsulate(decap_ctx, NULL, &secret_dec_len,
                             ciphertext, ciphertext_len) <= 0) {
        fprintf(stderr, "Decapsulation initialization failed.\n");
        goto cleanup;
    }

    secret_dec = malloc(secret_dec_len);

    if (!secret_dec ||
        EVP_PKEY_decapsulate(decap_ctx, secret_dec, &secret_dec_len,
                             ciphertext, ciphertext_len) <= 0) {
        fprintf(stderr, "Decapsulation failed.\n");
        goto cleanup;
    }

    if (secret_enc_len != secret_dec_len ||
        CRYPTO_memcmp(secret_enc, secret_dec, secret_enc_len) != 0) {
        fprintf(stderr, "Shared secrets do not match.\n");
        goto cleanup;
    }

    printf("ML-KEM-768 key generation: SUCCESS\n");
    printf("ML-KEM-768 encapsulation: SUCCESS\n");
    printf("ML-KEM-768 decapsulation: SUCCESS\n");
    printf("Shared secret verification: SUCCESS\n");

    result = EXIT_SUCCESS;

cleanup:
    if (result != EXIT_SUCCESS)
        ERR_print_errors_fp(stderr);

    if (private_key) {
        OPENSSL_cleanse(private_key, private_len);
        free(private_key);
    }
    if (secret_enc) {
        OPENSSL_cleanse(secret_enc, secret_enc_len);
        free(secret_enc);
    }
    if (secret_dec) {
        OPENSSL_cleanse(secret_dec, secret_dec_len);
        free(secret_dec);
    }

    free(public_key);
    free(ciphertext);

    EVP_PKEY_CTX_free(keygen_ctx);
    EVP_PKEY_CTX_free(encap_ctx);
    EVP_PKEY_CTX_free(decap_ctx);
    EVP_PKEY_free(keypair);

    return result;
}

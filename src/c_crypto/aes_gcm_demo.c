#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#define KEY_SIZE 32
#define NONCE_SIZE 12
#define TAG_SIZE 16

int main(void) {
    unsigned char key[KEY_SIZE];
    unsigned char nonce[NONCE_SIZE];
    unsigned char ciphertext[256];
    unsigned char decrypted[256];
    unsigned char tag[TAG_SIZE];

    const unsigned char plaintext[] =
        "QuantumVault AES-256-GCM encryption test";

    int len = 0;
    int ciphertext_len = 0;
    int decrypted_len = 0;
    int result = EXIT_FAILURE;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (!ctx) {
        fprintf(stderr, "Cipher context creation failed.\n");
        goto cleanup;
    }

    if (RAND_bytes(key, KEY_SIZE) != 1 ||
        RAND_bytes(nonce, NONCE_SIZE) != 1) {
        fprintf(stderr, "Secure random generation failed.\n");
        goto cleanup;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL,
                           key, nonce) != 1) {
        fprintf(stderr, "Encryption initialization failed.\n");
        goto cleanup;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len,
                          plaintext, sizeof(plaintext) - 1) != 1) {
        fprintf(stderr, "Encryption failed.\n");
        goto cleanup;
    }

    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        fprintf(stderr, "Encryption finalization failed.\n");
        goto cleanup;
    }

    ciphertext_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                            TAG_SIZE, tag) != 1) {
        fprintf(stderr, "Tag retrieval failed.\n");
        goto cleanup;
    }

    EVP_CIPHER_CTX_reset(ctx);

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL,
                           key, nonce) != 1) {
        fprintf(stderr, "Decryption initialization failed.\n");
        goto cleanup;
    }

    if (EVP_DecryptUpdate(ctx, decrypted, &len,
                          ciphertext, ciphertext_len) != 1) {
        fprintf(stderr, "Decryption failed.\n");
        goto cleanup;
    }

    decrypted_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                            TAG_SIZE, tag) != 1) {
        fprintf(stderr, "Tag setup failed.\n");
        goto cleanup;
    }

    if (EVP_DecryptFinal_ex(ctx, decrypted + len, &len) != 1) {
        fprintf(stderr, "Authentication failed. Data may be modified.\n");
        goto cleanup;
    }

    decrypted_len += len;
    decrypted[decrypted_len] = '\0';

    printf("AES-256-GCM encryption: SUCCESS\n");
    printf("AES-256-GCM decryption: SUCCESS\n");
    printf("Authentication verification: SUCCESS\n");
    printf("Decrypted message: %s\n", decrypted);

    result = EXIT_SUCCESS;

cleanup:
    OPENSSL_cleanse(key, sizeof(key));
    EVP_CIPHER_CTX_free(ctx);

    return result;
}

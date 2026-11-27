#ifndef QUANTUMVAULT_CRYPTO_H
#define QUANTUMVAULT_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

int qv_generate_keypair(const char *key_directory);

int qv_encrypt_file(
    const char *key_directory,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t **encrypted,
    size_t *encrypted_len
);

int qv_decrypt_file(
    const char *key_directory,
    const uint8_t *encrypted,
    size_t encrypted_len,
    uint8_t **plaintext,
    size_t *plaintext_len
);

void qv_free_buffer(uint8_t *buffer, size_t buffer_len);

#endif

#define _POSIX_C_SOURCE 200809L
#include "quantumvault_crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

#define QV_KEY_ALGORITHM "ML-KEM-768"
#define QV_PRIVATE_KEY_FILE "private.pem"
#define QV_PUBLIC_KEY_FILE "public.pem"
#define QV_KEY_LEN 32
#define QV_NONCE_LEN 12
#define QV_TAG_LEN 16
#define QV_SALT_LEN 32

int qv_generate_keypair(const char *key_directory) {
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;
    char private_path[PATH_MAX];
    char public_path[PATH_MAX];
    FILE *private_file = NULL;
    FILE *public_file = NULL;
    int result = 0;

    if (!key_directory || !*key_directory)
        return 0;

    if (mkdir(key_directory, 0700) != 0 && errno != EEXIST)
        return 0;

    struct stat st;
    if (stat(key_directory, &st) != 0 || !S_ISDIR(st.st_mode) ||
        st.st_uid != geteuid())
        return 0;

    if (chmod(key_directory, 0700) != 0)
        return 0;

    int private_len = snprintf(private_path, sizeof(private_path), "%s/%s",
                               key_directory, QV_PRIVATE_KEY_FILE);
    int public_len = snprintf(public_path, sizeof(public_path), "%s/%s",
                              key_directory, QV_PUBLIC_KEY_FILE);
    if (private_len < 0 || (size_t)private_len >= sizeof(private_path) ||
        public_len < 0 || (size_t)public_len >= sizeof(public_path))
        return 0;

    if (access(private_path, F_OK) == 0 || access(public_path, F_OK) == 0)
        return 0;

    ctx = EVP_PKEY_CTX_new_from_name(NULL, QV_KEY_ALGORITHM, NULL);
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_generate(ctx, &key) <= 0)
        goto cleanup;

    int private_fd = open(private_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (private_fd < 0)
        goto cleanup;

    private_file = fdopen(private_fd, "wb");
    if (!private_file) {
        close(private_fd);
        unlink(private_path);
        goto cleanup;
    }

    if (!PEM_write_PrivateKey(private_file, key, NULL, NULL, 0, NULL, NULL) ||
        fflush(private_file) != 0 || fsync(fileno(private_file)) != 0)
        goto cleanup;

    if (fclose(private_file) != 0) {
        private_file = NULL;
        goto cleanup;
    }
    private_file = NULL;

    int public_fd = open(public_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (public_fd < 0)
        goto cleanup;

    public_file = fdopen(public_fd, "wb");
    if (!public_file) {
        close(public_fd);
        unlink(public_path);
        goto cleanup;
    }

    if (!PEM_write_PUBKEY(public_file, key) ||
        fflush(public_file) != 0 || fsync(fileno(public_file)) != 0)
        goto cleanup;

    if (fclose(public_file) != 0) {
        public_file = NULL;
        goto cleanup;
    }
    public_file = NULL;

    result = 1;

cleanup:
    if (private_file)
        fclose(private_file);
    if (public_file)
        fclose(public_file);
    if (!result) {
        unlink(private_path);
        unlink(public_path);
    }
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    return result;
}

static int qv_derive_aes_key(
    const unsigned char *secret,
    size_t secret_len,
    const unsigned char *salt,
    unsigned char *aes_key
) {
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *ctx = NULL;
    int success = 0;

    char digest[] = "SHA256";
    char mode[] = "EXTRACT_AND_EXPAND";
    const unsigned char info[] = "QuantumVault file encryption v1";

    if (!secret || !secret_len || !salt || !aes_key)
        return 0;

    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf)
        goto cleanup;

    ctx = EVP_KDF_CTX_new(kdf);
    if (!ctx)
        goto cleanup;

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(
            OSSL_KDF_PARAM_DIGEST, digest, 0),
        OSSL_PARAM_construct_utf8_string(
            OSSL_KDF_PARAM_MODE, mode, 0),
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_KEY, (void *)secret, secret_len),
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SALT, (void *)salt, QV_SALT_LEN),
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_INFO, (void *)info, sizeof(info) - 1),
        OSSL_PARAM_construct_end()
    };

    if (EVP_KDF_derive(ctx, aes_key, QV_KEY_LEN, params) <= 0)
        goto cleanup;

    success = 1;

cleanup:
    EVP_KDF_CTX_free(ctx);
    EVP_KDF_free(kdf);
    return success;
}

int qv_encrypt_file(
    const char *key_directory,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t **encrypted,
    size_t *encrypted_len
) {
    EVP_PKEY *public_key = NULL;
    EVP_PKEY_CTX *kem_ctx = NULL;
    EVP_CIPHER_CTX *cipher_ctx = NULL;
    FILE *key_file = NULL;

    unsigned char *kem_ciphertext = NULL;
    unsigned char *shared_secret = NULL;
    unsigned char aes_key[QV_KEY_LEN] = {0};

    unsigned char salt[QV_SALT_LEN];
    unsigned char nonce[QV_NONCE_LEN];
    unsigned char *output = NULL;

    size_t kem_len = 0;
    size_t secret_len = 0;
    size_t total_len = 0;
    size_t header_len = 51;

    char public_path[PATH_MAX];
    int path_len;
    int out_len = 0;
    int final_len = 0;
    int success = 0;

    if (!key_directory || !*key_directory ||
        (!plaintext && plaintext_len != 0) ||
        !encrypted || !encrypted_len ||
        plaintext_len > INT_MAX)
        return 0;

    *encrypted = NULL;
    *encrypted_len = 0;

    path_len = snprintf(public_path, sizeof(public_path),
                        "%s/%s", key_directory, QV_PUBLIC_KEY_FILE);
    if (path_len < 0 || (size_t)path_len >= sizeof(public_path))
        goto cleanup;

    key_file = fopen(public_path, "rb");
    if (!key_file)
        goto cleanup;

    public_key = PEM_read_PUBKEY(key_file, NULL, NULL, NULL);
    fclose(key_file);
    key_file = NULL;

    if (!public_key)
        goto cleanup;

    kem_ctx = EVP_PKEY_CTX_new(public_key, NULL);
    if (!kem_ctx ||
        EVP_PKEY_encapsulate_init(kem_ctx, NULL) <= 0 ||
        EVP_PKEY_encapsulate(kem_ctx, NULL, &kem_len,
                             NULL, &secret_len) <= 0 ||
        kem_len > UINT16_MAX)
        goto cleanup;

    kem_ciphertext = OPENSSL_malloc(kem_len);
    shared_secret = OPENSSL_malloc(secret_len);
    if (!kem_ciphertext || !shared_secret ||
        EVP_PKEY_encapsulate(kem_ctx, kem_ciphertext, &kem_len,
                             shared_secret, &secret_len) <= 0)
        goto cleanup;

    if (RAND_bytes(salt, sizeof(salt)) != 1 ||
        RAND_bytes(nonce, sizeof(nonce)) != 1 ||
        !qv_derive_aes_key(shared_secret, secret_len, salt, aes_key))
        goto cleanup;

    if (plaintext_len > SIZE_MAX - header_len - kem_len - QV_TAG_LEN)
        goto cleanup;

    total_len = header_len + kem_len + plaintext_len + QV_TAG_LEN;
    output = OPENSSL_malloc(total_len);
    if (!output)
        goto cleanup;

    memcpy(output, "QVLT", 4);
    output[4] = 1;
    output[5] = (unsigned char)(kem_len >> 8);
    output[6] = (unsigned char)(kem_len & 0xff);
    memcpy(output + 7, salt, QV_SALT_LEN);
    memcpy(output + 7 + QV_SALT_LEN, nonce, QV_NONCE_LEN);
    memcpy(output + header_len, kem_ciphertext, kem_len);

    cipher_ctx = EVP_CIPHER_CTX_new();
    if (!cipher_ctx ||
        EVP_EncryptInit_ex(cipher_ctx, EVP_aes_256_gcm(),
                           NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_IVLEN,
                            QV_NONCE_LEN, NULL) != 1 ||
        EVP_EncryptInit_ex(cipher_ctx, NULL, NULL,
                           aes_key, nonce) != 1)
        goto cleanup;

    if (plaintext_len > 0 &&
        EVP_EncryptUpdate(cipher_ctx, output + header_len + kem_len,
                          &out_len, plaintext,
                          (int)plaintext_len) != 1)
        goto cleanup;

    if (EVP_EncryptFinal_ex(
            cipher_ctx,
            output + header_len + kem_len + out_len,
            &final_len) != 1)
        goto cleanup;

    if (EVP_CIPHER_CTX_ctrl(
            cipher_ctx, EVP_CTRL_GCM_GET_TAG, QV_TAG_LEN,
            output + total_len - QV_TAG_LEN) != 1)
        goto cleanup;

    *encrypted = output;
    *encrypted_len = total_len;
    output = NULL;
    success = 1;

cleanup:
    if (key_file)
        fclose(key_file);

    OPENSSL_cleanse(aes_key, sizeof(aes_key));
    OPENSSL_cleanse(shared_secret, secret_len);
    OPENSSL_clear_free(shared_secret, secret_len);
    OPENSSL_clear_free(kem_ciphertext, kem_len);
    OPENSSL_clear_free(output, total_len);

    EVP_CIPHER_CTX_free(cipher_ctx);
    EVP_PKEY_CTX_free(kem_ctx);
    EVP_PKEY_free(public_key);

    return success;
}

int qv_decrypt_file(
    const char *key_directory,
    const uint8_t *encrypted,
    size_t encrypted_len,
    uint8_t **plaintext,
    size_t *plaintext_len
) {
    EVP_PKEY *private_key = NULL;
    EVP_PKEY_CTX *kem_ctx = NULL;
    EVP_CIPHER_CTX *cipher_ctx = NULL;
    FILE *key_file = NULL;

    unsigned char *shared_secret = NULL;
    unsigned char aes_key[QV_KEY_LEN] = {0};
    unsigned char *output = NULL;

    size_t header_len = 51;
    size_t kem_len = 0;
    size_t secret_len = 0;
    size_t ciphertext_len = 0;
    size_t output_len = 0;

    char private_path[PATH_MAX];
    int path_len;
    int out_len = 0;
    int final_len = 0;
    int success = 0;

    if (!key_directory || !*key_directory ||
        !encrypted || !plaintext || !plaintext_len ||
        encrypted_len < header_len + QV_TAG_LEN ||
        encrypted_len > INT_MAX)
        return 0;

    *plaintext = NULL;
    *plaintext_len = 0;

    if (memcmp(encrypted, "QVLT", 4) != 0 || encrypted[4] != 1)
        goto cleanup;

    kem_len = ((size_t)encrypted[5] << 8) | encrypted[6];

    if (kem_len == 0 ||
        kem_len > encrypted_len - header_len - QV_TAG_LEN)
        goto cleanup;

    ciphertext_len = encrypted_len - header_len - kem_len - QV_TAG_LEN;

    path_len = snprintf(private_path, sizeof(private_path),
                        "%s/%s", key_directory, QV_PRIVATE_KEY_FILE);
    if (path_len < 0 || (size_t)path_len >= sizeof(private_path))
        goto cleanup;

    key_file = fopen(private_path, "rb");
    if (!key_file)
        goto cleanup;

    private_key = PEM_read_PrivateKey(key_file, NULL, NULL, NULL);
    fclose(key_file);
    key_file = NULL;

    if (!private_key)
        goto cleanup;

    kem_ctx = EVP_PKEY_CTX_new(private_key, NULL);
    if (!kem_ctx ||
        EVP_PKEY_decapsulate_init(kem_ctx, NULL) <= 0 ||
        EVP_PKEY_decapsulate(kem_ctx, NULL, &secret_len,
                             encrypted + header_len, kem_len) <= 0)
        goto cleanup;

    shared_secret = OPENSSL_malloc(secret_len);
    if (!shared_secret ||
        EVP_PKEY_decapsulate(kem_ctx, shared_secret, &secret_len,
                             encrypted + header_len, kem_len) <= 0)
        goto cleanup;

    if (!qv_derive_aes_key(shared_secret, secret_len,
                           encrypted + 7, aes_key))
        goto cleanup;

    output_len = ciphertext_len ? ciphertext_len : 1;
    output = OPENSSL_malloc(output_len);
    if (!output)
        goto cleanup;

    cipher_ctx = EVP_CIPHER_CTX_new();
    if (!cipher_ctx ||
        EVP_DecryptInit_ex(cipher_ctx, EVP_aes_256_gcm(),
                           NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_IVLEN,
                            QV_NONCE_LEN, NULL) != 1 ||
        EVP_DecryptInit_ex(cipher_ctx, NULL, NULL, aes_key,
                           encrypted + 7 + QV_SALT_LEN) != 1)
        goto cleanup;

    if (ciphertext_len > 0 &&
        EVP_DecryptUpdate(cipher_ctx, output, &out_len,
                          encrypted + header_len + kem_len,
                          (int)ciphertext_len) != 1)
        goto cleanup;

    if (EVP_CIPHER_CTX_ctrl(
            cipher_ctx, EVP_CTRL_GCM_SET_TAG, QV_TAG_LEN,
            (void *)(encrypted + encrypted_len - QV_TAG_LEN)) != 1)
        goto cleanup;

    if (EVP_DecryptFinal_ex(cipher_ctx, output + out_len,
                            &final_len) != 1)
        goto cleanup;

    *plaintext = output;
    *plaintext_len = (size_t)(out_len + final_len);
    output = NULL;
    success = 1;

cleanup:
    if (key_file)
        fclose(key_file);

    OPENSSL_cleanse(aes_key, sizeof(aes_key));
    OPENSSL_clear_free(shared_secret, secret_len);
    OPENSSL_clear_free(output, output_len);

    EVP_CIPHER_CTX_free(cipher_ctx);
    EVP_PKEY_CTX_free(kem_ctx);
    EVP_PKEY_free(private_key);

    return success;
}

void qv_free_buffer(uint8_t *buffer, size_t buffer_len) {
    if (buffer)
        OPENSSL_clear_free(buffer, buffer_len);
}

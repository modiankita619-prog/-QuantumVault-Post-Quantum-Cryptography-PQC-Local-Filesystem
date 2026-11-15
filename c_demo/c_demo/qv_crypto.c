#include "qv_crypto.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

/* If your liboqs is older than 0.11, use OQS_KEM_alg_kyber_768 instead. */
#define KEM_ALG   OQS_KEM_alg_ml_kem_768
#define NONCE_LEN 12
#define TAG_LEN   16
#define KEY_LEN   32

static int gcm_enc(const uint8_t *key, const uint8_t *nonce,
                   const uint8_t *pt, size_t n, uint8_t *ct, uint8_t *tag)
{
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int len, ok = 0;
    if (!c) return -1;
    if (EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto end;
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) != 1) goto end;
    if (EVP_EncryptInit_ex(c, NULL, NULL, key, nonce) != 1) goto end;
    if (n > 0 && EVP_EncryptUpdate(c, ct, &len, pt, (int)n) != 1) goto end;
    if (EVP_EncryptFinal_ex(c, ct + n, &len) != 1) goto end;
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1) goto end;
    ok = 1;
end:
    EVP_CIPHER_CTX_free(c);
    return ok ? 0 : -1;
}

static int gcm_dec(const uint8_t *key, const uint8_t *nonce,
                   const uint8_t *ct, size_t n, const uint8_t *tag, uint8_t *pt)
{
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int len, ok = 0;
    if (!c) return -1;
    if (EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto end;
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) != 1) goto end;
    if (EVP_DecryptInit_ex(c, NULL, NULL, key, nonce) != 1) goto end;
    if (n > 0 && EVP_DecryptUpdate(c, pt, &len, ct, (int)n) != 1) goto end;
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void *)tag) != 1) goto end;
    if (EVP_DecryptFinal_ex(c, pt + n, &len) <= 0) goto end;   /* tag check */
    ok = 1;
end:
    EVP_CIPHER_CTX_free(c);
    return ok ? 0 : -1;
}

static size_t kem_field(int which)
{
    OQS_KEM *k = OQS_KEM_new(KEM_ALG);
    size_t v = 0;
    if (!k) return 0;
    if (which == 0) v = k->length_public_key;
    if (which == 1) v = k->length_secret_key;
    if (which == 2) v = k->length_ciphertext + NONCE_LEN + TAG_LEN;
    OQS_KEM_free(k);
    return v;
}

size_t qv_pk_len(void)   { return kem_field(0); }
size_t qv_sk_len(void)   { return kem_field(1); }
size_t qv_overhead(void) { return kem_field(2); }

int qv_keypair(uint8_t *pk, uint8_t *sk)
{
    OQS_KEM *k = OQS_KEM_new(KEM_ALG);
    int rc;
    if (!k) return -1;
    rc = (OQS_KEM_keypair(k, pk, sk) == OQS_SUCCESS) ? 0 : -1;
    OQS_KEM_free(k);
    return rc;
}

int qv_encrypt(const uint8_t *pk, const uint8_t *pt, size_t pt_len,
               uint8_t *out, size_t out_cap, size_t *out_len)
{
    int rc = -1;
    OQS_KEM *k = OQS_KEM_new(KEM_ALG);
    uint8_t *ss = NULL, *ct, *nonce, *tag, *body;
    size_t need;

    if (!k) return -1;
    need = k->length_ciphertext + NONCE_LEN + TAG_LEN + pt_len;
    if (out_cap < need || k->length_shared_secret != KEY_LEN || pt_len > INT_MAX) goto end;

    ss = malloc(KEY_LEN);
    if (!ss) goto end;

    ct    = out;
    nonce = ct + k->length_ciphertext;
    tag   = nonce + NONCE_LEN;
    body  = tag + TAG_LEN;

    if (OQS_KEM_encaps(k, ct, ss, pk) != OQS_SUCCESS) goto end;
    if (RAND_bytes(nonce, NONCE_LEN) != 1) goto end;
    if (gcm_enc(ss, nonce, pt, pt_len, body, tag) != 0) goto end;

    *out_len = need;
    rc = 0;
end:
    if (ss) { OQS_MEM_cleanse(ss, KEY_LEN); free(ss); }
    OQS_KEM_free(k);
    return rc;
}

int qv_decrypt(const uint8_t *sk, const uint8_t *blob, size_t blob_len,
               uint8_t *out, size_t out_cap, size_t *out_len)
{
    int rc = -1;
    OQS_KEM *k = OQS_KEM_new(KEM_ALG);
    uint8_t *ss = NULL;
    const uint8_t *ct, *nonce, *tag, *body;
    size_t hdr, pt_len;

    if (!k) return -1;
    hdr = k->length_ciphertext + NONCE_LEN + TAG_LEN;
    if (blob_len < hdr) goto end;
    pt_len = blob_len - hdr;
    if (out_cap < pt_len || k->length_shared_secret != KEY_LEN || pt_len > INT_MAX) goto end;

    ss = malloc(KEY_LEN);
    if (!ss) goto end;

    ct    = blob;
    nonce = ct + k->length_ciphertext;
    tag   = nonce + NONCE_LEN;
    body  = tag + TAG_LEN;

    if (OQS_KEM_decaps(k, ss, ct, sk) != OQS_SUCCESS) goto end;
    if (gcm_dec(ss, nonce, body, pt_len, tag, out) != 0) goto end;  /* fails if tampered */

    *out_len = pt_len;
    rc = 0;
end:
    if (ss) { OQS_MEM_cleanse(ss, KEY_LEN); free(ss); }
    OQS_KEM_free(k);
    return rc;
}

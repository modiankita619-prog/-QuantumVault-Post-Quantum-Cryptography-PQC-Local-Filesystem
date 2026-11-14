#ifndef QV_CRYPTO_H
#define QV_CRYPTO_H
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

size_t qv_pk_len(void);
size_t qv_sk_len(void);
size_t qv_overhead(void);   /* bytes added to plaintext: KEM ct + nonce + tag */

int qv_keypair(uint8_t *pk, uint8_t *sk);
int qv_encrypt(const uint8_t *pk, const uint8_t *pt, size_t pt_len,
               uint8_t *out, size_t out_cap, size_t *out_len);
int qv_decrypt(const uint8_t *sk, const uint8_t *blob, size_t blob_len,
               uint8_t *out, size_t out_cap, size_t *out_len);

#ifdef __cplusplus
}
#endif
#endif

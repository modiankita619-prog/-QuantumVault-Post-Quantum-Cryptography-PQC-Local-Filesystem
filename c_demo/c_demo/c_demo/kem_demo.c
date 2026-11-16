#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>
#include "qv_crypto.h"

static void hex(const char *label, const uint8_t *b, size_t n)
{
    printf("%s", label);
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
    printf("...\n");
}

int main(void)
{
    /* ---- Part 1: raw KEM steps ---- */
    OQS_KEM *k = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!k) { fprintf(stderr, "ML-KEM-768 not enabled in this liboqs build\n"); return 1; }

    printf("Algorithm : %s\n", k->method_name);
    printf("pk=%zu sk=%zu ct=%zu ss=%zu bytes\n", k->length_public_key,
           k->length_secret_key, k->length_ciphertext, k->length_shared_secret);

    uint8_t *pk = malloc(k->length_public_key), *sk = malloc(k->length_secret_key);
    uint8_t *ct = malloc(k->length_ciphertext);
    uint8_t *ss_a = malloc(k->length_shared_secret), *ss_b = malloc(k->length_shared_secret);

    if (OQS_KEM_keypair(k, pk, sk) != OQS_SUCCESS) return 1;
    if (OQS_KEM_encaps(k, ct, ss_a, pk) != OQS_SUCCESS) return 1;   /* sender side   */
    if (OQS_KEM_decaps(k, ss_b, ct, sk) != OQS_SUCCESS) return 1;   /* receiver side */

    hex("secret (encaps): ", ss_a, 8);
    hex("secret (decaps): ", ss_b, 8);
    printf("Shared secrets match: %s\n\n",
           memcmp(ss_a, ss_b, k->length_shared_secret) == 0 ? "YES" : "NO");

    /* ---- Part 2: encrypt a string (KEM + AES-256-GCM) ---- */
    const char *msg = "Project Phoenix blueprint - TOP SECRET";
    size_t mlen = strlen(msg), ov = qv_overhead(), outlen = 0, declen = 0;
    uint8_t *blob = malloc(mlen + ov);
    uint8_t *plain = malloc(mlen + 1);

    if (qv_encrypt(pk, (const uint8_t *)msg, mlen, blob, mlen + ov, &outlen) != 0) {
        fprintf(stderr, "encrypt failed\n"); return 1;
    }
    printf("Plaintext : %s (%zu bytes)\n", msg, mlen);
    hex("Encrypted : ", blob, 24);
    printf("Blob size : %zu bytes\n", outlen);

    if (qv_decrypt(sk, blob, outlen, plain, mlen, &declen) != 0) {
        fprintf(stderr, "decrypt failed\n"); return 1;
    }
    plain[declen] = 0;
    printf("Decrypted : %s\n", plain);

    /* ---- Part 3: tamper test ---- */
    blob[outlen - 1] ^= 0x01;
    printf("Tampered blob decrypt: %s\n",
           qv_decrypt(sk, blob, outlen, plain, mlen, &declen) != 0 ? "REJECTED (good)" : "accepted (BAD)");

    OQS_MEM_cleanse(sk, k->length_secret_key);
    OQS_MEM_cleanse(ss_a, k->length_shared_secret);
    OQS_MEM_cleanse(ss_b, k->length_shared_secret);
    OQS_KEM_free(k);
    return 0;
}

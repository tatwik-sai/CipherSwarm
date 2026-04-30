#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>

#define SHA1_DIGEST_LEN 20
#define SHA1_HEX_SIZE   41   /* 40 hex chars + null */

/*
 * CipherSwarm Crypto Utilities
 * Uses a built-in SHA1 implementation for piece hashing.
 * Token signing uses RSA-SHA256 (private key on auth server,
 * public key on peers).
 */

/* ── SHA1 Hashing ─────────────────────────────────────────── */

void sha1_hash(const void *data, size_t len, unsigned char *digest);
void sha1_hash_hex(const void *data, size_t len, char *hex_out);
int  sha1_verify(const void *data, size_t len, const char *expected_hex);
int  sha1_file(const char *filepath, char *hex_out);

/* ── RSA Token Signing ────────────────────────────────────── */

/* Generate RSA private/public keypair PEM files */
int generate_rsa_keypair(const char *private_key_path,
                         const char *public_key_path);

/* Sign data with RSA private key (SHA256). Returns 0 on success. */
int rsa_sign_with_private_key(const char *private_key_path,
                              const void *data, size_t data_len,
                              unsigned char *sig_out,
                              size_t sig_out_capacity,
                              size_t *sig_len_out);

/* Verify signature with RSA public key (SHA256). Returns 1 valid, 0 invalid. */
int rsa_verify_with_public_key(const char *public_key_path,
                               const void *data, size_t data_len,
                               const unsigned char *signature,
                               size_t signature_len);

#endif /* CRYPTO_H */

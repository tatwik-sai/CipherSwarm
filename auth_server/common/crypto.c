/*
 * ═══════════════════════════════════════════════════════════════
 *  CipherSwarm — Crypto Module (Self-Contained)
 *
 *  Built-in SHA1 implementation + RSA-SHA256 token signing.
 *
 *  SHA1 implementation based on RFC 3174.
 * ═══════════════════════════════════════════════════════════════
 */

#include "crypto.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>


typedef struct {
    unsigned int  state[5];
    unsigned int  count[2];
    unsigned char buffer[64];
} SHA1_CTX;

#define SHA1_ROL(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

#define SHA1_BLK0(i) (block[i] = (block[i] << 24) | ((block[i] & 0xFF00) << 8) | \
                      ((block[i] >> 8) & 0xFF00) | (block[i] >> 24))
#define SHA1_BLK(i)  (block[i & 15] = SHA1_ROL(block[(i+13) & 15] ^ block[(i+8) & 15] ^ \
                      block[(i+2) & 15] ^ block[i & 15], 1))

#define SHA1_R0(v,w,x,y,z,i) z += ((w & (x ^ y)) ^ y) + SHA1_BLK0(i) + 0x5A827999 + SHA1_ROL(v, 5); w = SHA1_ROL(w, 30);
#define SHA1_R1(v,w,x,y,z,i) z += ((w & (x ^ y)) ^ y) + SHA1_BLK(i) + 0x5A827999 + SHA1_ROL(v, 5); w = SHA1_ROL(w, 30);
#define SHA1_R2(v,w,x,y,z,i) z += (w ^ x ^ y) + SHA1_BLK(i) + 0x6ED9EBA1 + SHA1_ROL(v, 5); w = SHA1_ROL(w, 30);
#define SHA1_R3(v,w,x,y,z,i) z += (((w | x) & y) | (w & x)) + SHA1_BLK(i) + 0x8F1BBCDC + SHA1_ROL(v, 5); w = SHA1_ROL(w, 30);
#define SHA1_R4(v,w,x,y,z,i) z += (w ^ x ^ y) + SHA1_BLK(i) + 0xCA62C1D6 + SHA1_ROL(v, 5); w = SHA1_ROL(w, 30);

static void sha1_transform(unsigned int state[5], const unsigned char buf[64])
{
    unsigned int a, b, c, d, e;
    unsigned int block[16];

    memcpy(block, buf, 64);

    a = state[0]; b = state[1]; c = state[2]; d = state[3]; e = state[4];

    SHA1_R0(a,b,c,d,e, 0); SHA1_R0(e,a,b,c,d, 1); SHA1_R0(d,e,a,b,c, 2); SHA1_R0(c,d,e,a,b, 3);
    SHA1_R0(b,c,d,e,a, 4); SHA1_R0(a,b,c,d,e, 5); SHA1_R0(e,a,b,c,d, 6); SHA1_R0(d,e,a,b,c, 7);
    SHA1_R0(c,d,e,a,b, 8); SHA1_R0(b,c,d,e,a, 9); SHA1_R0(a,b,c,d,e,10); SHA1_R0(e,a,b,c,d,11);
    SHA1_R0(d,e,a,b,c,12); SHA1_R0(c,d,e,a,b,13); SHA1_R0(b,c,d,e,a,14); SHA1_R0(a,b,c,d,e,15);
    SHA1_R1(e,a,b,c,d,16); SHA1_R1(d,e,a,b,c,17); SHA1_R1(c,d,e,a,b,18); SHA1_R1(b,c,d,e,a,19);
    SHA1_R2(a,b,c,d,e,20); SHA1_R2(e,a,b,c,d,21); SHA1_R2(d,e,a,b,c,22); SHA1_R2(c,d,e,a,b,23);
    SHA1_R2(b,c,d,e,a,24); SHA1_R2(a,b,c,d,e,25); SHA1_R2(e,a,b,c,d,26); SHA1_R2(d,e,a,b,c,27);
    SHA1_R2(c,d,e,a,b,28); SHA1_R2(b,c,d,e,a,29); SHA1_R2(a,b,c,d,e,30); SHA1_R2(e,a,b,c,d,31);
    SHA1_R2(d,e,a,b,c,32); SHA1_R2(c,d,e,a,b,33); SHA1_R2(b,c,d,e,a,34); SHA1_R2(a,b,c,d,e,35);
    SHA1_R2(e,a,b,c,d,36); SHA1_R2(d,e,a,b,c,37); SHA1_R2(c,d,e,a,b,38); SHA1_R2(b,c,d,e,a,39);
    SHA1_R3(a,b,c,d,e,40); SHA1_R3(e,a,b,c,d,41); SHA1_R3(d,e,a,b,c,42); SHA1_R3(c,d,e,a,b,43);
    SHA1_R3(b,c,d,e,a,44); SHA1_R3(a,b,c,d,e,45); SHA1_R3(e,a,b,c,d,46); SHA1_R3(d,e,a,b,c,47);
    SHA1_R3(c,d,e,a,b,48); SHA1_R3(b,c,d,e,a,49); SHA1_R3(a,b,c,d,e,50); SHA1_R3(e,a,b,c,d,51);
    SHA1_R3(d,e,a,b,c,52); SHA1_R3(c,d,e,a,b,53); SHA1_R3(b,c,d,e,a,54); SHA1_R3(a,b,c,d,e,55);
    SHA1_R3(e,a,b,c,d,56); SHA1_R3(d,e,a,b,c,57); SHA1_R3(c,d,e,a,b,58); SHA1_R3(b,c,d,e,a,59);
    SHA1_R4(a,b,c,d,e,60); SHA1_R4(e,a,b,c,d,61); SHA1_R4(d,e,a,b,c,62); SHA1_R4(c,d,e,a,b,63);
    SHA1_R4(b,c,d,e,a,64); SHA1_R4(a,b,c,d,e,65); SHA1_R4(e,a,b,c,d,66); SHA1_R4(d,e,a,b,c,67);
    SHA1_R4(c,d,e,a,b,68); SHA1_R4(b,c,d,e,a,69); SHA1_R4(a,b,c,d,e,70); SHA1_R4(e,a,b,c,d,71);
    SHA1_R4(d,e,a,b,c,72); SHA1_R4(c,d,e,a,b,73); SHA1_R4(b,c,d,e,a,74); SHA1_R4(a,b,c,d,e,75);
    SHA1_R4(e,a,b,c,d,76); SHA1_R4(d,e,a,b,c,77); SHA1_R4(c,d,e,a,b,78); SHA1_R4(b,c,d,e,a,79);

    state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e;
}

static void sha1_init(SHA1_CTX *ctx)
{
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
    ctx->count[0] = ctx->count[1] = 0;
}

static void sha1_update(SHA1_CTX *ctx, const unsigned char *data, size_t len)
{
    size_t i, j;
    j = (ctx->count[0] >> 3) & 63;
    if ((ctx->count[0] += (unsigned int)(len << 3)) < (unsigned int)(len << 3))
        ctx->count[1]++;
    ctx->count[1] += (unsigned int)(len >> 29);

    if ((j + len) > 63) {
        memcpy(&ctx->buffer[j], data, (i = 64 - j));
        sha1_transform(ctx->state, ctx->buffer);
        for (; i + 63 < len; i += 64)
            sha1_transform(ctx->state, &data[i]);
        j = 0;
    } else {
        i = 0;
    }
    memcpy(&ctx->buffer[j], &data[i], len - i);
}

static void sha1_final(unsigned char digest[20], SHA1_CTX *ctx)
{
    unsigned char finalcount[8];
    for (int i = 0; i < 8; i++)
        finalcount[i] = (unsigned char)((ctx->count[(i >= 4) ? 0 : 1]
                         >> ((3 - (i & 3)) * 8)) & 255);

    unsigned char c = 0200;
    sha1_update(ctx, &c, 1);
    while ((ctx->count[0] & 504) != 448) {
        c = 0;
        sha1_update(ctx, &c, 1);
    }
    sha1_update(ctx, finalcount, 8);

    for (int i = 0; i < 20; i++)
        digest[i] = (unsigned char)((ctx->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
}

/* ══════════════════════════════════════════════════════════════
 *  Public SHA1 API
 * ══════════════════════════════════════════════════════════════ */

void sha1_hash(const void *data, size_t len, unsigned char *digest)
{
    SHA1_CTX ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, (const unsigned char *)data, len);
    sha1_final(digest, &ctx);
}

void sha1_hash_hex(const void *data, size_t len, char *hex_out)
{
    unsigned char digest[SHA1_DIGEST_LEN];
    sha1_hash(data, len, digest);
    bytes_to_hex(digest, SHA1_DIGEST_LEN, hex_out);
}

int sha1_verify(const void *data, size_t len, const char *expected_hex)
{
    char computed[SHA1_HEX_SIZE];
    sha1_hash_hex(data, len, computed);
    return (strcmp(computed, expected_hex) == 0) ? 1 : 0;
}

int sha1_file(const char *filepath, char *hex_out)
{
    FILE *fp = fopen(filepath, "rb");
    if (!fp) return -1;

    SHA1_CTX ctx;
    sha1_init(&ctx);

    unsigned char buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0)
        sha1_update(&ctx, buf, n);

    unsigned char digest[SHA1_DIGEST_LEN];
    sha1_final(digest, &ctx);
    fclose(fp);

    bytes_to_hex(digest, SHA1_DIGEST_LEN, hex_out);
    return 0;
}

/* ══════════════════════════════════════════════════════════════
 *  RSA Key Management / Sign / Verify (via openssl CLI)
 * ══════════════════════════════════════════════════════════════ */

static int run_cmd(char *const argv[], int quiet)
{
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        if (quiet) {
            int devnull = open("/dev/null", O_WRONLY);
            if (devnull >= 0) {
                dup2(devnull, STDOUT_FILENO);
                dup2(devnull, STDERR_FILENO);
                if (devnull > STDERR_FILENO) close(devnull);
            }
        }
        execvp(argv[0], argv);
        _exit(127);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return -1;
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) return 0;
    return -1;
}

int generate_rsa_keypair(const char *private_key_path,
                         const char *public_key_path)
{
    char *gen_args[] = {
        (char *)"openssl", (char *)"genpkey",
        (char *)"-algorithm", (char *)"RSA",
        (char *)"-pkeyopt", (char *)"rsa_keygen_bits:2048",
        (char *)"-out", (char *)private_key_path,
        NULL
    };

    char *pub_args[] = {
        (char *)"openssl", (char *)"pkey",
        (char *)"-in", (char *)private_key_path,
        (char *)"-pubout",
        (char *)"-out", (char *)public_key_path,
        NULL
    };

    if (run_cmd(gen_args, 0) < 0) return -1;
    if (run_cmd(pub_args, 0) < 0) return -1;

    LOG_INFO("Generated RSA private key: %s", private_key_path);
    LOG_INFO("Generated RSA public key:  %s", public_key_path);
    return 0;
}

static int write_temp_file(const void *data, size_t len, char *path_out, size_t path_cap)
{
    char tmpl[] = "/tmp/cipherswarmXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) return -1;
    ssize_t written = write(fd, data, len);
    close(fd);
    if (written != (ssize_t)len) {
        unlink(tmpl);
        return -1;
    }
    safe_strncpy(path_out, tmpl, path_cap);
    return 0;
}

int rsa_sign_with_private_key(const char *private_key_path,
                              const void *data, size_t data_len,
                              unsigned char *sig_out,
                              size_t sig_out_capacity,
                              size_t *sig_len_out)
{
    char data_path[64];
    char sig_path[80];
    if (write_temp_file(data, data_len, data_path, sizeof(data_path)) < 0)
        return -1;

    snprintf(sig_path, sizeof(sig_path), "%s.sig", data_path);

    char *sign_args[] = {
        (char *)"openssl", (char *)"dgst",
        (char *)"-sha256",
        (char *)"-sign", (char *)private_key_path,
        (char *)"-out", sig_path,
        data_path,
        NULL
    };

    int ret = -1;
    FILE *fp = NULL;

    if (run_cmd(sign_args, 0) < 0) goto out;

    fp = fopen(sig_path, "rb");
    if (!fp) goto out;
    size_t n = fread(sig_out, 1, sig_out_capacity, fp);
    if (n == 0) goto out;
    *sig_len_out = n;
    ret = 0;

out:
    if (fp) fclose(fp);
    unlink(data_path);
    unlink(sig_path);
    return ret;
}

int rsa_verify_with_public_key(const char *public_key_path,
                               const void *data, size_t data_len,
                               const unsigned char *signature,
                               size_t signature_len)
{
    char data_path[64];
    char sig_path[80];
    if (write_temp_file(data, data_len, data_path, sizeof(data_path)) < 0)
        return 0;
    if (write_temp_file(signature, signature_len, sig_path, sizeof(sig_path)) < 0) {
        unlink(data_path);
        return 0;
    }

    char *verify_args[] = {
        (char *)"openssl", (char *)"dgst",
        (char *)"-sha256",
        (char *)"-verify", (char *)public_key_path,
        (char *)"-signature", sig_path,
        data_path,
        NULL
    };

    int valid = (run_cmd(verify_args, 1) == 0) ? 1 : 0;
    if (valid) {
        LOG_DEBUG("RSA signature verification succeeded");
    } else {
        LOG_DEBUG("RSA signature verification failed");
    }
    unlink(data_path);
    unlink(sig_path);
    return valid;
}

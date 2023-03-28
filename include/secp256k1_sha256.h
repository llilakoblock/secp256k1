/**********************************************************************
 * Copyright (c) 2014 Pieter Wuille                                   *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_HASH_
#define _SECP256K1_HASH_

#include <stddef.h>
#include <stdint.h>
#include "secp256k1.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t s[8];
    uint32_t buf[16]; /* In big endian */
    size_t bytes;
} secp256k1_sha256, secp256k1_sha256_t;

SECP256K1_API void secp256k1_sha256_initialize(secp256k1_sha256 *hash);
SECP256K1_API void secp256k1_sha256_write(secp256k1_sha256 *hash, const unsigned char *data, size_t size);
SECP256K1_API void secp256k1_sha256_finalize(secp256k1_sha256 *hash, unsigned char *out32);

typedef struct {
    secp256k1_sha256 inner, outer;
} secp256k1_hmac_sha256, secp256k1_hmac_sha256_t;

SECP256K1_API void secp256k1_hmac_sha256_initialize(secp256k1_hmac_sha256 *hash, const unsigned char *key, size_t size);
SECP256K1_API void secp256k1_hmac_sha256_write(secp256k1_hmac_sha256 *hash, const unsigned char *data, size_t size);
SECP256K1_API void secp256k1_hmac_sha256_finalize(secp256k1_hmac_sha256 *hash, unsigned char *out32);

typedef struct {
    unsigned char v[32];
    unsigned char k[32];
    int retry;
} secp256k1_rfc6979_hmac_sha256, secp256k1_rfc6979_hmac_sha256_t;

SECP256K1_API void secp256k1_rfc6979_hmac_sha256_initialize(secp256k1_rfc6979_hmac_sha256 *rng, const unsigned char *key, size_t keylen);
SECP256K1_API void secp256k1_rfc6979_hmac_sha256_generate(secp256k1_rfc6979_hmac_sha256 *rng, unsigned char *out, size_t outlen);
SECP256K1_API void secp256k1_rfc6979_hmac_sha256_finalize(secp256k1_rfc6979_hmac_sha256 *rng);

#ifdef __cplusplus
}
#endif

#endif

#ifndef CTR_DRBG_H

#define CTR_DRBG_H
#define RESEED_INTERVAL 10000
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "aes.h"
#include "key_expansion.h"

#define CTR_DRBG_ENTROPY_LEN 48

typedef struct {
    uint8_t Key[32];
    uint8_t V[16];
    uint64_t reseed_counter;
} CTR_DRBG_CTX;


void ctr_drbg_init(
    CTR_DRBG_CTX *ctx,
    const uint8_t *entropy, // Must be 48 bytes
    const uint8_t *personalization_string // Optional, up to 48 bytes
);

int ctr_drbg_generate(
    CTR_DRBG_CTX *ctx,
    uint8_t *output,
    size_t outlen,
    const uint8_t *additional_input // Optional, up to 48 bytes
);

void ctr_drbg_reseed(
    CTR_DRBG_CTX *ctx, 
    const uint8_t *new_entropy, // Must be 48 bytes
    const uint8_t *additional_input // Optional, up to 48 bytes
);

void ctr_drbg_uninstantiate(CTR_DRBG_CTX *ctx);

#endif
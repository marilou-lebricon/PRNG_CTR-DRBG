#ifndef CTR_DRBG_H
#define CTR_DRBG_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "aes.h"
#include "key_expansion.h"


typedef struct {
    uint8_t Key[32];
    uint8_t V[16];
    uint64_t reseed_counter;
} CTR_DRBG_CTX;


// Initialisation
void ctr_drbg_init(
    CTR_DRBG_CTX *ctx,
    const uint8_t *entropy,
    const uint8_t *nonce
);


// Génération pseudo-aléatoire
void ctr_drbg_generate(
    CTR_DRBG_CTX *ctx,
    uint8_t *output,
    size_t outlen
);

#endif
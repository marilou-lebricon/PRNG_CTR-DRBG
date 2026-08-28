#include "ctr_drbg.h"

// Incrémentation du compteur V (big-endian)
static void increment_V(uint8_t V[16]) {

    for (int i = 15; i >= 0; i--) {

        V[i]++;

        if (V[i] != 0) {
            break;
        }
    }
}

// Initialisation
void ctr_drbg_init(
    CTR_DRBG_CTX *ctx,
    const uint8_t *entropy,
    const uint8_t *nonce
) {
    memcpy(ctx->Key, entropy, 32);
    memcpy(ctx->V, nonce, 16);
    ctx->reseed_counter = 1;
}

// Génération
void ctr_drbg_generate(
    CTR_DRBG_CTX *ctx,
    uint8_t *output,
    size_t outlen
) {
    AESRoundKeys rk;
    KeyExpansion(ctx->Key, rk);

    size_t produced = 0;

    while (produced < outlen) {

        increment_V(ctx->V);

        uint8_t block[16];

        AES_encrypt_block(ctx->V, block, rk);

        size_t n = (outlen - produced > 16)
            ? 16
            : (outlen - produced);

        memcpy(output + produced, block, n);

        produced += n;

        memset(block, 0, sizeof(block));
    }

    ctx->reseed_counter++;

    memset(rk, 0, sizeof(rk));
}
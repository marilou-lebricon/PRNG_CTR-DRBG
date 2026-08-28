#include <stdio.h>
#include "ctr_drbg.h"

int main(void) {

    CTR_DRBG_CTX ctx;

    uint8_t entropy[32] = {0x00};
    uint8_t nonce[16]   = {0x01};

    uint8_t output[64];

    ctr_drbg_init(&ctx, entropy, nonce);
    ctr_drbg_generate(&ctx, output, sizeof(output));

    for (int i = 0; i < 64; i++) {

        printf("%02x", output[i]);

        if ((i + 1) % 16 == 0)
            printf("\n");
    }

    return 0;
}
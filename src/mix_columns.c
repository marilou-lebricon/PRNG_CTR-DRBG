#include "mix_columns.h"
#include "aes.h"


// Multiplication par 2 dans GF(2^8)
uint8_t multiply_by_2(uint8_t x) {
    if (x & 0x80) {
        return (x << 1) ^ 0x1b;  // Si le bit le plus significatif est 1, applique le XOR avec 0x1B
    } else {
        return x << 1;
    }
}

// Multiplication par 3 dans GF(2^8)
uint8_t multiply_by_3(uint8_t x) {
    return multiply_by_2(x) ^ x;
}

// Fonction MixColumns
void MixColumns(AESState state) {
    uint8_t temp[4];
    
    for (int i = 0; i < 4; i++) {
        // Copie les valeurs de la colonne i dans temp
        temp[0] = state[0][i];
        temp[1] = state[1][i];
        temp[2] = state[2][i];
        temp[3] = state[3][i];

        // Calcul des nouvelles valeurs pour la colonne i
        state[0][i] = multiply_by_2(temp[0]) ^ multiply_by_3(temp[1]) ^ temp[2] ^ temp[3];
        state[1][i] = temp[0] ^ multiply_by_2(temp[1]) ^ multiply_by_3(temp[2]) ^ temp[3];
        state[2][i] = temp[0] ^ temp[1] ^ multiply_by_2(temp[2]) ^ multiply_by_3(temp[3]);
        state[3][i] = multiply_by_3(temp[0]) ^ temp[1] ^ temp[2] ^ multiply_by_2(temp[3]);
    }
}

// Inverse de MixColumns :

// Multiplication dans GF(2^8)
uint8_t xtime(uint8_t x) {
    return (x << 1) ^ ((x >> 7) * 0x1b);
}

uint8_t multiply(uint8_t x, uint8_t by) {
    uint8_t res = 0;
    while (by) {
        if (by & 1)
            res ^= x;
        x = xtime(x);
        by >>= 1;
    }
    return res;
}

uint8_t multiply_by_9(uint8_t x)  { return multiply(x, 0x09); }
uint8_t multiply_by_11(uint8_t x) { return multiply(x, 0x0b); }
uint8_t multiply_by_13(uint8_t x) { return multiply(x, 0x0d); }
uint8_t multiply_by_14(uint8_t x) { return multiply(x, 0x0e); }

void InvMixColumns(AESState state) {
    uint8_t temp[4];

    for (int c = 0; c < 4; ++c) {
        temp[0] = multiply_by_14(state[0][c]) ^ multiply_by_11(state[1][c]) ^ multiply_by_13(state[2][c]) ^ multiply_by_9(state[3][c]);
        temp[1] = multiply_by_9(state[0][c])  ^ multiply_by_14(state[1][c]) ^ multiply_by_11(state[2][c]) ^ multiply_by_13(state[3][c]);
        temp[2] = multiply_by_13(state[0][c]) ^ multiply_by_9(state[1][c])  ^ multiply_by_14(state[2][c]) ^ multiply_by_11(state[3][c]);
        temp[3] = multiply_by_11(state[0][c]) ^ multiply_by_13(state[1][c]) ^ multiply_by_9(state[2][c])  ^ multiply_by_14(state[3][c]);

        for (int r = 0; r < 4; ++r)
            state[r][c] = temp[r];
    }
}
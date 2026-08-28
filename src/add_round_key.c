#include "add_round_key.h"
#include "aes.h"

void AddRoundKey(AESState state, const uint8_t *roundKey) {
    for (int col = 0; col < Nb; col++) {
        // chaque colonne a 4 lignes (4 octets)
        for (int row = 0; row < 4; row++) {
            // on applique un XOR entre l'octe du state et l'octet de la clé de ronde correspondante
            // roundKey est un tableau linéaire de 16 octets, organisé en colonne de 4 octets
            state[row][col] ^= roundKey[col*4 + row];
        }
    }
}
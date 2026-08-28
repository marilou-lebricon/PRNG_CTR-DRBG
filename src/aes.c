#include "aes.h"
#include "sub_bytes.h"
#include "shift_rows.h"
#include "key_expansion.h"
#include "mix_columns.h"
#include "add_round_key.h"
#include "tables.h"



void AES_encrypt_block(const AESBlock in, AESBlock out, const AESRoundKeys roundKeys) {
    AESState state;
    int round;

    // copier les données du block d'entrée vers la matrice d'état (colonne par colonne)
    for (int col = 0; col < Nb; col++) {
        for (int row = 0; row < 4; row++) {
            state[row][col] = in[col*4 + row];
        }
    }
     // Ronde initiale (AddRoundKey)
     AddRoundKey(state, roundKeys); // roundKeys = w[0]

     // 9 rondes principales
     for (round = 1; round < Nr; round++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, roundKeys + Nb*round*4); // chaque round = 16 octets // décalage de round
     }

     // Dernière ronde (sans MixColumns)
     SubBytes(state);
     ShiftRows(state);
     AddRoundKey(state, roundKeys + Nr*Nb*4); // 160 = 10 * 16 = offset (décalage en octets) pour accéder à la dernière clé de ronde dans le tableau roundKeys

     // Copier la matrice d'état vers le bloc de sortie (colonne par colonne)
     for (int col = 0; col < Nb; col++) {
        for (int row = 0; row < 4; row++) {
            out[col*4 + row] = state[row][col];
        }
     }
}

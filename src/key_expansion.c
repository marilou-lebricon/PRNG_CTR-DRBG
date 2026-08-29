#include "key_expansion.h"
#include "aes.h"
#include "tables.h"

// ---------------------------------------------------------------------------------------------
// Fonctions utilitaires sur les mots
// ---------------------------------------------------------------------------------------------

// Rotation gauche d’un mot de 32 bits d’un octet
static word RotWord(word w) {
    return (w << 8) | (w >> 24);
}

// Application de la S-box sur chaque octet du mot
static word SubWord(word w) {
    return ((word)sbox[(w >> 24) & 0xFF] << 24) |
           ((word)sbox[(w >> 16) & 0xFF] << 16) |
           ((word)sbox[(w >> 8)  & 0xFF] << 8)  |
           ((word)sbox[(w)       & 0xFF]);
}

// ---------------------------------------------------------------------------------------------
// Expansion de clé AES-256
// ---------------------------------------------------------------------------------------------

void KeyExpansion(const uint8_t* key, AESRoundKeys roundKeys) {

    // AES-256 :
    // Nb = 4
    // Nk = 8
    // Nr = 14
    //
    // Nombre total de mots :
    // Nb * (Nr + 1) = 4 * 15 = 60

    word w[Nb * (Nr + 1)];

    word temp;

    int i;

    // Copie de la clé initiale dans les 8 premiers mots
    for (i = 0; i < Nk; i++) {

        w[i] =
            ((word)key[4 * i]     << 24) |
            ((word)key[4 * i + 1] << 16) |
            ((word)key[4 * i + 2] << 8)  |
            ((word)key[4 * i + 3]);
    }

    // Génération des mots suivants
    for (i = Nk; i < Nb * (Nr + 1); i++) {

        temp = w[i - 1];

        // Cas spécial AES
        if (i % Nk == 0) {

            temp = SubWord(RotWord(temp)) ^ Rcon[i / Nk];
        }

        // Cas supplémentaire AES-256
        else if (i % Nk == 4) {

            temp = SubWord(temp);
        }

        w[i] = w[i - Nk] ^ temp;
    }

    // Conversion des mots vers le tableau d’octets roundKeys[]
    for (i = 0; i < Nb * (Nr + 1); i++) {

        roundKeys[4 * i]     = (w[i] >> 24) & 0xFF;
        roundKeys[4 * i + 1] = (w[i] >> 16) & 0xFF;
        roundKeys[4 * i + 2] = (w[i] >> 8)  & 0xFF;
        roundKeys[4 * i + 3] = (w[i])       & 0xFF;
    }
}
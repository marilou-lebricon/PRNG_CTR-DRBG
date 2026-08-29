#include "sub_bytes.h"
#include "aes.h"
#include "tables.h" // contient la Sbox

void SubBytes(AESState state) {
    for (int row = 0; row < 4; ++row) {
        for (int col = 0; col < Nb; ++col) {
            state[row][col] = sbox[state[row][col]];
        }
    }
}

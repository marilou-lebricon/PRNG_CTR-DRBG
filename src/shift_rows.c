#include "shift_rows.h"
#include "aes.h"

void ShiftRows(AESState state) {
    uint8_t temp;
    // ligne 1 : décalage de 1 à gauche
    temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;

    // ligne 2 : décalage de 2 à gauche
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    //ligne 3 : décalage de 3 à gauche (= 1 à droite)
    
    temp = state[3][0];
    state[3][0] = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = temp;
}

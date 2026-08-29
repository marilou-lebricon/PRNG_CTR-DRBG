#ifndef ADD_ROUND_KEY_H
#define ADD_ROUND_KEY_H

#include "aes.h"

void AddRoundKey(AESState state, const uint8_t *roundKey);

#endif // ADD_ROUND_KEY_H
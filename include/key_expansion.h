#ifndef KEY_EXPANSION_H
#define KEY_EXPANSION_H

#include "aes.h"

void KeyExpansion(const uint8_t* key, AESRoundKeys roundKeys);

#endif // KEY_EXPANSION_H
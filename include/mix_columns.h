#ifndef MIX_COLUMNS_H
#define MIX_COLUMNS_H

#include "aes.h"

uint8_t multiply_by_2(uint8_t x);
uint8_t multiply_by_3(uint8_t x);
void MixColumns(AESState state);

uint8_t xtime(uint8_t x);
uint8_t multiply(uint8_t x, uint8_t by);
uint8_t multiply_by_9(uint8_t x);
uint8_t multiply_by_11(uint8_t x);
uint8_t multiply_by_13(uint8_t x);
uint8_t multiply_by_14(uint8_t x);
void InvMixColumns(AESState state);


#endif // MIX_COLUMNS_H
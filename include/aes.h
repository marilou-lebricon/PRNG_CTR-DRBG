#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <stddef.h>

#define Nb 4
#define Nk 8
#define Nr 14

typedef uint32_t word;

#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 32
#define AES_ROUND_KEY_SIZE 240

typedef uint8_t AESBlock[AES_BLOCK_SIZE];
typedef uint8_t AESState[4][4];
typedef uint8_t AESRoundKeys[AES_ROUND_KEY_SIZE];

void AES_encrypt_block(const AESBlock in,AESBlock out,const AESRoundKeys roundKeys);

#endif
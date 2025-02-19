#ifndef BLOWFISH_H
#define BLOWFISH_H

#include <stdint.h>



// Blowfish context structure
typedef struct {
    uint32_t P[16 + 2];  // P-array
    uint32_t S[4][256];               // S-boxes
} BLOWFISH_CTX;

//  Declare P-array and S-boxes (Defined in `blowfish.c`)
extern  uint32_t ORIG_P[16+ 2];
extern  uint32_t ORIG_S[4][256];

//  Function prototypes
void Blowfish_Init(BLOWFISH_CTX *ctx, uint8_t *key, int32_t keyLen);
void Blowfish_Encrypt(BLOWFISH_CTX *ctx, uint32_t *xl, uint32_t *xr);
void Blowfish_Decrypt(BLOWFISH_CTX *ctx, uint32_t *xl, uint32_t *xr);

//  CBC Mode Prototypes
void Blowfish_Encrypt_CBC(BLOWFISH_CTX *ctx, uint8_t *data, uint8_t *iv, size_t length);
void Blowfish_Decrypt_CBC(BLOWFISH_CTX *ctx, uint8_t *data, uint8_t *iv, size_t length);

#endif // BLOWFISH_H

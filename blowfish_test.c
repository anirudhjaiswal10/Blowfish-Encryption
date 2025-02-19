#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>  // For random IV generation
#include <time.h>    // For seeding randomness
#include "blowfish.h"

//  Function to print data in hex format
void print_hex(uint8_t *data, size_t length) {
    for (size_t i = 0; i < length; i++) {
        printf("%02X ", data[i]);
    }
    printf("\n");
}

//  Function to compare plaintext and decrypted text
int verify_decryption(uint8_t *original, uint8_t *decrypted, size_t length) {
    return memcmp(original, decrypted, length) == 0;
}

//  Generate a random IV for CBC mode
void generate_random_iv(uint8_t *iv, size_t length) {
    for (size_t i = 0; i < length; i++) {
        iv[i] = rand() % 256;  // Random byte value between 0-255
    }
}

int main() {
    //  Seed the random generator for IV randomness
    srand(time(NULL));

    //  Blowfish Key
    uint8_t key[] = "mysecretkey";  

    //  Generate a new random IV
    uint8_t iv[8];
    generate_random_iv(iv, 8);

    //  Save the IV before encryption
    uint8_t original_iv[8];
    memcpy(original_iv, iv, 8);

    //  Plaintext (Must be a multiple of 8 bytes)
    uint8_t plaintext[16] = "HelloWorld123456";  

    //  Buffers for encryption and decryption
    uint8_t ciphertext[16];
    uint8_t decrypted[16];

    //  Initialize Blowfish context (Key Expansion happens here)
    BLOWFISH_CTX ctx;
    printf("[INFO] Initializing Blowfish with Key Expansion...\n");
    Blowfish_Init(&ctx, key, strlen((char *)key));

    printf("\n[INFO] Original Plaintext:\n");
    print_hex(plaintext, 16);

    printf("\n[INFO] Using Random IV:\n");
    print_hex(iv, 8);

    //  Encrypt in CBC Mode
    memcpy(ciphertext, plaintext, 16);
    printf("\n[INFO] Starting CBC Encryption...\n");
    Blowfish_Encrypt_CBC(&ctx, ciphertext, iv, 16);
    printf("\n[INFO] Ciphertext after Blowfish CBC Encryption:\n");
    print_hex(ciphertext, 16);

    //  Restore IV before decryption
    memcpy(iv, original_iv, 8);

    //  Decrypt in CBC Mode
    memcpy(decrypted, ciphertext, 16);
    printf("\n[INFO] Starting CBC Decryption...\n");
    Blowfish_Decrypt_CBC(&ctx, decrypted, iv, 16);
    printf("\n[INFO] Decrypted Plaintext after Blowfish CBC Decryption:\n");
    print_hex(decrypted, 16);

    //  Verify if decryption is correct
    if (verify_decryption(plaintext, decrypted, 16)) {
        printf("\n[SUCCESS] Blowfish CBC Mode Decryption Matches Original Plaintext!\n");
    } else {
        printf("\n[ERROR] Blowfish CBC Mode Decryption FAILED! Decrypted text does not match original plaintext.\n");
    }

    return 0;
}

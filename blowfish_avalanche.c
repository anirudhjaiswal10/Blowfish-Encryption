#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "blowfish.h"

#define BLOCK_SIZE 8   // Blowfish block size (64-bit)
#define ITERATIONS 10  // Number of iterations for averaging avalanche effect

// Optimized Hamming distance calculation using __builtin_popcount()
int hamming_distance(uint8_t *x, uint8_t *y, size_t length) {
    int count = 0;
    for (size_t i = 0; i < length; i++) {
        count += __builtin_popcount(x[i] ^ y[i]); // Fast bit count
    }
    return count;
}

// Function to calculate avalanche effect for Blowfish CBC mode
double calculate_avalanche_effect(BLOWFISH_CTX *ctx, uint8_t *plaintext, uint8_t *key) {
    uint8_t iv[BLOCK_SIZE] = {0};  // Fixed IV for consistency
    uint8_t encrypted[BLOCK_SIZE], flipped_encrypted[BLOCK_SIZE];

    // Encrypt original plaintext
    Blowfish_Encrypt_CBC(ctx, plaintext, iv, BLOCK_SIZE);
    memcpy(encrypted, plaintext, BLOCK_SIZE);

    // Flip a bit in the middle of the plaintext (more balanced impact)
    plaintext[BLOCK_SIZE / 2] ^= 0x01;

    // Reset IV and encrypt modified plaintext
    Blowfish_Encrypt_CBC(ctx, plaintext, iv, BLOCK_SIZE);
    memcpy(flipped_encrypted, plaintext, BLOCK_SIZE);

    // Restore original plaintext (undo bit flip)
    plaintext[BLOCK_SIZE / 2] ^= 0x01;

    // Compute and return normalized avalanche effect
    return (hamming_distance(encrypted, flipped_encrypted, BLOCK_SIZE) / (double)(BLOCK_SIZE * 8)) * 100.0;
}

int main() {
    BLOWFISH_CTX ctx;
    uint8_t key[BLOCK_SIZE] = "testkey"; // 8-byte Blowfish key
    uint8_t plaintext[BLOCK_SIZE] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};

    // Initialize Blowfish with the key
    Blowfish_Init(&ctx, key, BLOCK_SIZE);

    double total_avalanche = 0.0;

    // Run multiple iterations to compute average avalanche effect
    for (int i = 0; i < ITERATIONS; i++) {
        total_avalanche += calculate_avalanche_effect(&ctx, plaintext, key);
    }

    // Print final result
    printf("Average Avalanche Effect over %d iterations: %.2f%%\n", ITERATIONS, total_avalanche / ITERATIONS);

    return 0;
}


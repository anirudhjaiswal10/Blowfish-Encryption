#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "blowfish.h"  // Ensure you have a working Blowfish header

#define BLOCK_SIZE 8  // Blowfish block size (64-bit blocks)
#define ITERATIONS 10 // Number of iterations for averaging

// Optimized Hamming distance function using __builtin_popcount()
int hamming_distance(const uint8_t *a, const uint8_t *b, size_t length) {
    int distance = 0;
    for (size_t i = 0; i < length; i++) {
        distance += __builtin_popcount(a[i] ^ b[i]); // Faster bit counting
    }
    return distance;
}

// Function to compute correlation over multiple iterations
double calculate_avg_correlation(BLOWFISH_CTX *ctx, uint8_t *plaintext, uint8_t *key, size_t key_len) {
    uint8_t iv[BLOCK_SIZE] = {0};  // Fixed IV for consistency
    uint8_t original_ciphertext[BLOCK_SIZE], modified_ciphertext[BLOCK_SIZE];
    uint8_t modified_key[BLOCK_SIZE];
    double total_correlation = 0.0;

    for (int i = 0; i < ITERATIONS; i++) {
        // Encrypt with the original key
        uint8_t input[BLOCK_SIZE];
        memcpy(input, plaintext, BLOCK_SIZE);
        memset(iv, 0, BLOCK_SIZE);  // Reset IV
        Blowfish_Encrypt_CBC(ctx, input, iv, BLOCK_SIZE);
        memcpy(original_ciphertext, input, BLOCK_SIZE);

        // Modify the key (flip a bit in the middle)
        memcpy(modified_key, key, key_len);
        modified_key[key_len / 2] ^= 0x01; // Flip 1 bit in the middle of the key

        // Reinitialize Blowfish with the modified key
        Blowfish_Init(ctx, modified_key, key_len);

        // Encrypt again with the modified key
        memcpy(input, plaintext, BLOCK_SIZE);
        memset(iv, 0, BLOCK_SIZE);  // Reset IV
        Blowfish_Encrypt_CBC(ctx, input, iv, BLOCK_SIZE);
        memcpy(modified_ciphertext, input, BLOCK_SIZE);

        // Compute Hamming distance
        int hamming_dist = hamming_distance(original_ciphertext, modified_ciphertext, BLOCK_SIZE);

        // Normalized Correlation Calculation
        total_correlation += (hamming_dist / (double)(BLOCK_SIZE * 8)) * 100.0;
    }

    return total_correlation / ITERATIONS; // Return average correlation
}

int main() {
    BLOWFISH_CTX ctx;
    uint8_t key[BLOCK_SIZE] = "testkey";  // 8-byte Blowfish key
    uint8_t plaintext[BLOCK_SIZE] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};

    // Initialize Blowfish with the original key
    Blowfish_Init(&ctx, key, BLOCK_SIZE);

    // Calculate and print only the average correlation
    double avg_correlation = calculate_avg_correlation(&ctx, plaintext, key, BLOCK_SIZE);
    printf("Average Correlation over %d iterations: %.2f%%\n", ITERATIONS, avg_correlation);

    return 0;
}



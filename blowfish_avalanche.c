#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "blowfish.h"

// Function to calculate Hamming distance between two values
int hamming_distance(uint32_t x, uint32_t y) {
    uint32_t diff = x ^ y; // XOR to find differing bits
    int count = 0;
    while (diff) {
        count += diff & 1; // Count the set bits
        diff >>= 1;
    }
    return count;
}

// Function to calculate the avalanche effect
void calculate_avalanche_effect(BLOWFISH_CTX *ctx, uint32_t left, uint32_t right) {
    uint32_t encrypted_left, encrypted_right;
    uint32_t flipped_left, flipped_right;

    // Encrypt original values
    encrypted_left = left;
    encrypted_right = right;
    Blowfish_Encrypt(ctx, &encrypted_left, &encrypted_right);

    printf("\nOriginal Encryption:\n");
    printf("Left: %08X\n", encrypted_left);
    printf("Right: %08X\n", encrypted_right);

    // Modify a single bit in the left input
    flipped_left = left ^ 0x00000001; // Flip the least significant bit
    flipped_right = right;           // Keep the right part unchanged

    // Encrypt the modified values
    uint32_t flipped_encrypted_left = flipped_left;
    uint32_t flipped_encrypted_right = flipped_right;
    Blowfish_Encrypt(ctx, &flipped_encrypted_left, &flipped_encrypted_right);

    printf("\nFlipped Encryption (1-bit change):\n");
    printf("Left: %08X\n", flipped_encrypted_left);
    printf("Right: %08X\n", flipped_encrypted_right);

    // Calculate Hamming distance between the original and flipped encryption
    int left_hamming = hamming_distance(encrypted_left, flipped_encrypted_left);
    int right_hamming = hamming_distance(encrypted_right, flipped_encrypted_right);

    printf("\nAvalanche Effect:\n");
    printf("Hamming Distance (Left): %d bits\n", left_hamming);
    printf("Hamming Distance (Right): %d bits\n", right_hamming);

    // Normalized Avalanche Effect (Percentage)
    double left_percentage = (left_hamming / 32.0) * 100.0;
    double right_percentage = (right_hamming / 32.0) * 100.0;

    printf("Normalized Avalanche Effect (Left): %.2f%%\n", left_percentage);
    printf("Normalized Avalanche Effect (Right): %.2f%%\n", right_percentage);
}

int main() {
    BLOWFISH_CTX ctx;
    const char *key = "testkey"; // Key for encryption
    uint32_t left = 0x01234567;   // Original left value
    uint32_t right = 0x89ABCDEF;  // Original right value

    // Initialize Blowfish with the key
    Blowfish_Init(&ctx, (uint8_t *)key, strlen(key));

    // Calculate the avalanche effect
    calculate_avalanche_effect(&ctx, left, right);

    return 0;
}


#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "blowfish.h"  // Assuming you've got a working Blowfish header

// Function to print the hexadecimal representation of a 32-bit data
void print_hex(const char *label, uint32_t x) {
    printf("%s: %08X\n", label, x);
}

// Function to compute the Hamming Distance between two 32-bit values
int hamming_distance(uint32_t a, uint32_t b) {
    uint32_t diff = a ^ b;  // XOR the two values to find differing bits
    int distance = 0;
    
    // Count the number of differing bits (1s in diff)
    while (diff) {
        distance += diff & 1;  // If the last bit is 1, increment the distance
        diff >>= 1;  // Right shift to check the next bit
    }
    
    return distance;
}

// Function to calculate the normalized correlation (inverse of Hamming distance)
void calculate_correlation(uint32_t original_left, uint32_t original_right, 
                           uint32_t modified_left, uint32_t modified_right) {
    // Calculate Hamming distance for both left and right ciphertext parts
    int hamming_left = hamming_distance(original_left, modified_left);
    int hamming_right = hamming_distance(original_right, modified_right);
    
    // Normalize the Hamming distance (Maximum Hamming distance for 32-bit is 32)
    double normalized_left = (hamming_left / 32.0) * 100.0;
    double normalized_right = (hamming_right / 32.0) * 100.0;
    
    // Print the results: Hamming distance and normalized correlation
    printf("\nHamming Distance (Left): %d bits\n", hamming_left);
    printf("Hamming Distance (Right): %d bits\n", hamming_right);
    printf("Normalized Correlation (Left): %.2f%%\n", normalized_left);
    printf("Normalized Correlation (Right): %.2f%%\n", normalized_right);
}

// Function to assess correlation by modifying the key and comparing ciphertexts
void assess_correlation(BLOWFISH_CTX *ctx, uint32_t left, uint32_t right, uint8_t *key, uint32_t key_len) {
    // Original encryption with the original key
    uint32_t original_left = left;
    uint32_t original_right = right;
    uint32_t modified_left, modified_right;
    
    // Encrypt the original data with the original key
    Blowfish_Encrypt(ctx, &original_left, &original_right);
    
    // Modify the key (flip one bit in the key)
    uint8_t modified_key[8];  // Blowfish supports 4-56 byte keys, using 8-byte here
    memcpy(modified_key, key, key_len);  // Copy original key
    modified_key[0] ^= 0x01;  // Flip one bit (change the first byte)

    // Reinitialize the Blowfish context with the modified key
   Blowfish_Init(ctx, modified_key, key_len);  // Reinitialize with modified key
    
    // Encrypt the data again with the modified key
    modified_left = left;
    modified_right = right;
    Blowfish_Encrypt(ctx, &modified_left, &modified_right);
    
    // Calculate and print the correlation between the original and modified ciphertexts
    calculate_correlation(original_left, original_right, modified_left, modified_right);
}

int main() {
    // Define the Blowfish context and a sample key
    BLOWFISH_CTX ctx;
    uint8_t key[8] = "testkey";  // 8-byte key for Blowfish
    uint32_t left = 0x01234567;  // Predefined left part of the plaintext
    uint32_t right = 0x89ABCDEF;  // Predefined right part of the plaintext

    // Initialize Blowfish with the original key
    Blowfish_Init(&ctx, key, 8);

    printf("Original Data:\n");
    print_hex("Left", left);
    print_hex("Right", right);

    // Assess correlation after modifying the key
    assess_correlation(&ctx, left, right, key, 8);
    return 0;
}


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include "blowfish.h"  // Include Blowfish header for the necessary functions and context

#define KEY_SIZE 56      // Blowfish maximum key size (56 bytes)
#define DATA_SIZE 10240  // Example data size for testing (10 KB)

// Function to calculate entropy
double calculate_entropy(uint8_t *data, size_t len) {
    int freq[256] = {0};
    for (size_t i = 0; i < len; ++i) {
        freq[data[i]]++;
    }

    double entropy = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / len;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

int main() {
    uint8_t key[KEY_SIZE];         // Blowfish 56-byte key
    uint8_t data[DATA_SIZE];       // Random data to encrypt
    uint8_t encrypted_data[DATA_SIZE]; // Array to hold encrypted data

    // Initialize random key and data
    generate_random_key(key, KEY_SIZE); 
    generate_random_data(data, DATA_SIZE);

    // Debug: Print first few bytes of the key and data
    printf("Random Key (first 16 bytes): ");
    for (int i = 0; i < 16; i++) {
        printf("%02X ", key[i]);
    }
    printf("\n");

    printf("Random Data (first 16 bytes): ");
    for (int i = 0; i < 16; i++) {
        printf("%02X ", data[i]);
    }
    printf("\n");

    // Initialize Blowfish
    BLOWFISH_CTX ctx;
    BLOWFISH_INIT(&ctx, key, KEY_SIZE);

    // Encrypt the data in blocks
    uint32_t left, right;
    for (size_t i = 0; i < DATA_SIZE; i += 8) {
        left = *((uint32_t*) (data + i));
        right = *((uint32_t*) (data + i + 4));

        // Encrypt the block of data
        BLOWFISH_ENCRYPT(&ctx, &left, &right);

        // Store encrypted data back into the array
        *((uint32_t*) (encrypted_data + i)) = left;
        *((uint32_t*) (encrypted_data + i + 4)) = right;
    }

    // Calculate entropy of the encrypted data
    double entropy = calculate_entropy(encrypted_data, DATA_SIZE);
    printf("Entropy of encrypted data: %.4f bits per byte\n", entropy);

    return 0;
}

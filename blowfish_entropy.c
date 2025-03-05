#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include "blowfish.h"  // Blowfish implementation header

#define KEY_SIZE 56       // Blowfish max key size (56 bytes)
#define DATA_SIZE 10240   // Example data size for testing (10 KB)
#define BLOCK_SIZE 8      // Blowfish block size (64-bit = 8 bytes)

// Function to generate a random key
void generate_random_key(uint8_t *key, int key_size) {
    srand(time(NULL));
    for (int i = 0; i < key_size; i++) {
        key[i] = rand() % 256;
    }
}

// Function to generate random data
void generate_random_data(uint8_t *data, int data_size) {
    srand(time(NULL));
    for (int i = 0; i < data_size; i++) {
        data[i] = rand() % 256;
    }
}

// Function to generate a random IV
void generate_random_iv(uint8_t *iv, int block_size) {
    srand(time(NULL));
    for (int i = 0; i < block_size; i++) {
        iv[i] = rand() % 256;
    }
}

// Function to calculate entropy
double calculate_entropy(uint8_t *data, size_t len) {
    int freq[256] = {0}; // Frequency array for byte values (0-255)
    for (size_t i = 0; i < len; ++i) {
        freq[data[i]]++; // Count occurrences of each byte
    }

    double entropy = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / len;
            entropy -= p * log2(p); // Shannon entropy formula
        }
    }
    return entropy;
}

// CBC mode encryption function
void blowfish_encrypt_cbc(BLOWFISH_CTX *ctx, uint8_t *data, uint8_t *encrypted_data, uint8_t *iv, size_t data_size) {
    uint8_t prev_block[BLOCK_SIZE];
    memcpy(prev_block, iv, BLOCK_SIZE); // Initialize IV

    for (size_t i = 0; i < data_size; i += BLOCK_SIZE) {
        // XOR plaintext block with previous ciphertext block (or IV for the first block)
        for (int j = 0; j < BLOCK_SIZE; j++) {
            data[i + j] ^= prev_block[j];
        }

        // Encrypt the block
        uint32_t left = *((uint32_t *)(data + i));
        uint32_t right = *((uint32_t *)(data + i + 4));
        Blowfish_Encrypt(ctx, &left, &right);

        // Store encrypted data
        *((uint32_t *)(encrypted_data + i)) = left;
        *((uint32_t *)(encrypted_data + i + 4)) = right;

        // Update previous block with current ciphertext
        memcpy(prev_block, encrypted_data + i, BLOCK_SIZE);
    }
}

int main() {
    uint8_t key[KEY_SIZE];             // Blowfish key
    uint8_t iv[BLOCK_SIZE];            // IV for CBC mode
    uint8_t data[DATA_SIZE];           // Random input data
    uint8_t encrypted_data[DATA_SIZE]; // Array to store encrypted output

    // Generate random key, IV, and data
    generate_random_key(key, KEY_SIZE);
    generate_random_iv(iv, BLOCK_SIZE);
    generate_random_data(data, DATA_SIZE);

    // Initialize Blowfish context
    BLOWFISH_CTX ctx;
    Blowfish_Init(&ctx, key, KEY_SIZE);

    // Encrypt using CBC mode
    blowfish_encrypt_cbc(&ctx, data, encrypted_data, iv, DATA_SIZE);

    // Calculate entropy of the encrypted data
    double entropy = calculate_entropy(encrypted_data, DATA_SIZE);
    printf("Entropy of encrypted data (CBC Mode): %.4f bits per byte\n", entropy);

    return 0;
}


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include "blowfish.h"  // Blowfish implementation header

#define KEY_SIZE 56       // Blowfish max key size (56 bytes)
#define BLOCK_SIZE 8      // Blowfish block size (64-bit = 8 bytes)
#define ITERATIONS 10     // Number of iterations for averaging entropy

// Data sizes in bytes
size_t data_sizes[] = {8, 16, 50, 200, 500, 1024, 100 * 1024, 250 * 1024, 500 * 1024, 750 * 1024, 1024 * 1024};
const char *size_labels[] = {"8B", "16B", "50B", "200B", "500B", "1KB", "100KB", "250KB", "500KB", "750KB", "1MB"};

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

// CBC mode encryption function for Blowfish
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

// Function to compute Blowfish CBC entropy for a given data size
double compute_blowfish_cbc_entropy(size_t data_size, uint8_t *key) {
    uint8_t *data = (uint8_t *)malloc(data_size);
    uint8_t iv[BLOCK_SIZE];
    uint8_t encrypted_data[1024 * 1024]; // Maximum size used for encrypted data
    double total_entropy = 0.0;

    if (!data) {
        fprintf(stderr, "Memory allocation failed!\n");
        exit(1);
    }

    // Initialize Blowfish context
    BLOWFISH_CTX ctx;
    Blowfish_Init(&ctx, key, KEY_SIZE);

    for (int iter = 0; iter < ITERATIONS; iter++) {
        // Generate random IV and data for each iteration
        generate_random_iv(iv, BLOCK_SIZE);
        generate_random_data(data, data_size);

        // Encrypt using CBC mode
        blowfish_encrypt_cbc(&ctx, data, encrypted_data, iv, data_size);

        // Calculate entropy of the encrypted data and accumulate
        total_entropy += calculate_entropy(encrypted_data, data_size);
    }

    // Compute and return overall average entropy
    double avg_entropy = total_entropy / ITERATIONS;
    free(data);
    return avg_entropy;
}

int main() {
    srand(time(NULL));
    uint8_t key[KEY_SIZE]; // Blowfish key

    // Generate random key
    generate_random_key(key, KEY_SIZE);

    // Open the CSV file to write results
    FILE *csv_file = fopen("blowfish_cbc_entropy_results.csv", "w");
    if (!csv_file) {
        fprintf(stderr, "Failed to open CSV file for writing.\n");
        return 1;
    }

    // Write the header row
    fprintf(csv_file, "Data Size (Bytes),Average Entropy (bits/byte)\n");

    // Loop through each data size and compute entropy, then write to CSV
    for (int i = 0; i < sizeof(data_sizes) / sizeof(data_sizes[0]); i++) {
        double avg_entropy = compute_blowfish_cbc_entropy(data_sizes[i], key);
        fprintf(csv_file, "%s,%.6f\n", size_labels[i], avg_entropy);
    }

    // Close the CSV file
    fclose(csv_file);

    printf("Entropy results have been written to blowfish_cbc_entropy_results.csv\n");

    return 0;
}



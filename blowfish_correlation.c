#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include "blowfish.h"

#define BLOCK_SIZE 8   // Blowfish block size in bytes
#define SAMPLE_SIZE 10 // Number of iterations for correlation test

// Function to compute correlation coefficient
double compute_correlation(const uint8_t *plaintext, const uint8_t *ciphertext, size_t length) {
    double sum_plain = 0, sum_cipher = 0, sum_plain_cipher = 0;
    double sum_plain_sq = 0, sum_cipher_sq = 0;
    int n = length * 8;  // Total number of bits
    
    // Calculate correlation between plaintext and ciphertext bit-by-bit
    for (size_t i = 0; i < length; i++) {
        for (int bit = 0; bit < 8; bit++) {
            int p_bit = (plaintext[i] >> bit) & 1;  // Extract the bit from the plaintext
            int c_bit = (ciphertext[i] >> bit) & 1; // Extract the bit from the ciphertext
            
            sum_plain += p_bit;
            sum_cipher += c_bit;
            sum_plain_cipher += p_bit * c_bit;
            sum_plain_sq += p_bit * p_bit;
            sum_cipher_sq += c_bit * c_bit;
        }
    }
    
    // Compute the Pearson correlation coefficient
    double numerator = (n * sum_plain_cipher) - (sum_plain * sum_cipher);
    double denominator = sqrt((n * sum_plain_sq - sum_plain * sum_plain) * (n * sum_cipher_sq - sum_cipher * sum_cipher));
    
    // Return the correlation coefficient, checking for division by zero
    return (denominator == 0) ? 0 : (numerator / denominator);
}

// Blowfish encryption function in CBC mode (using Blowfish's own encryption function)
void blowfish_encrypt_cbc(const uint8_t *input, uint8_t *output, BLOWFISH_CTX *ctx, uint8_t *iv) {
    uint8_t block[BLOCK_SIZE];
    uint8_t previous_ciphertext[BLOCK_SIZE];
    
    // Copy the IV to initialize the previous ciphertext (used in CBC mode)
    memcpy(previous_ciphertext, iv, BLOCK_SIZE);

    // XOR the plaintext with the previous ciphertext (or IV for the first block)
    for (int i = 0; i < BLOCK_SIZE; i++) {
        block[i] = input[i] ^ previous_ciphertext[i];
    }

    // Perform encryption with Blowfish in CBC mode
    Blowfish_Encrypt_CBC(ctx, block, iv, BLOCK_SIZE);

    // Store the output ciphertext and update previous ciphertext for next block
    memcpy(output, block, BLOCK_SIZE);
    memcpy(previous_ciphertext, output, BLOCK_SIZE);  // Update the previous ciphertext for chaining
}

// Function to run the correlation test and write results to a file
void test_correlation(BLOWFISH_CTX *ctx, uint8_t *key) {
    srand(time(NULL));  // Seed the random number generator
    FILE *file = fopen("correlation_results.txt", "w");
    if (file == NULL) {
        printf("Error opening file!\n");
        return;
    }

    fprintf(file, "=== Blowfish CBC Mode Correlation Results ===\n");

    double total_correlation = 0.0;  // Variable to accumulate correlation for all iterations

    for (int i = 0; i < SAMPLE_SIZE; i++) {
        uint8_t plaintext[BLOCK_SIZE], ciphertext[BLOCK_SIZE], iv[BLOCK_SIZE];

        // Generate random plaintext and IV for each iteration
        for (int j = 0; j < BLOCK_SIZE; j++) {
            plaintext[j] = rand() % 256;
            iv[j] = rand() % 256;  // Random IV to ensure unpredictability
        }

        // Perform encryption in CBC mode with the random IV
        blowfish_encrypt_cbc(plaintext, ciphertext, ctx, iv);

        // Compute the correlation between plaintext and ciphertext
        double correlation = compute_correlation(plaintext, ciphertext, BLOCK_SIZE);
        total_correlation += correlation;

        // Write the plaintext, ciphertext, and correlation to the file for this iteration
        fprintf(file, "Iteration %d:\n", i + 1);
        fprintf(file, "Plaintext: ");
        for (int j = 0; j < BLOCK_SIZE; j++) {
            fprintf(file, "%02X", plaintext[j]);
        }
        fprintf(file, "\nCiphertext: ");
        for (int j = 0; j < BLOCK_SIZE; j++) {
            fprintf(file, "%02X", ciphertext[j]);
        }
        fprintf(file, "\nCorrelation: %.6f\n\n", correlation);
    }

    // Print the overall average correlation to the file
    double avg_correlation = total_correlation / SAMPLE_SIZE;
    double correlation_percentage = fabs(avg_correlation) * 100;
    fprintf(file, "\n=== Overall Correlation Result ===\n");
    fprintf(file, "Average Correlation: %.6f\n", avg_correlation);
    fprintf(file, "Correlation Effect: %.2f%%\n", correlation_percentage);

    fclose(file);  // Close the file
}

int main() {
    BLOWFISH_CTX ctx;
    uint8_t key[BLOCK_SIZE] = "testkey";  // Example key (8 bytes for Blowfish)

    // Initialize Blowfish with the original key
    Blowfish_Init(&ctx, key, BLOCK_SIZE);

    // Run the correlation test
    test_correlation(&ctx, key);

    return 0;
}



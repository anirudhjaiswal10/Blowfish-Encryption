#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include "blowfish.h" // Include your Blowfish header file

#define BLOCK_SIZE 8  // Blowfish block size in bytes
#define NUM_ITERATIONS 10  // Number of iterations to run the test
#define FLIP_BIT 1  // The bit to flip (always bit 1)

// Function to count bit differences (Hamming distance) between two byte arrays
int count_bit_difference(const uint8_t *a, const uint8_t *b, size_t length) {
    int count = 0;
    for (size_t i = 0; i < length; i++) {
        count += __builtin_popcount(a[i] ^ b[i]);
    }
    return count;
}

// Function to print data in hexadecimal format
void print_hex(FILE *file, const uint8_t *data, size_t length) {
    for (size_t i = 0; i < length; i++) {
        fprintf(file, "%02X", data[i]);
    }
}

void test_avalanche_effect(BLOWFISH_CTX *ctx, uint8_t *key, const uint8_t *plaintext, double *total_avalanche, FILE *file) {
    uint8_t iv[BLOCK_SIZE];
    uint8_t ciphertext_original[BLOCK_SIZE], ciphertext_modified[BLOCK_SIZE];

    // Generate random IV
    for (int i = 0; i < BLOCK_SIZE; i++) {
        iv[i] = rand() % 256;
    }

    // Encrypt the original plaintext
    uint8_t temp_plaintext[BLOCK_SIZE];
    memcpy(temp_plaintext, plaintext, BLOCK_SIZE); // Copy plaintext to avoid modifying the original
    Blowfish_Encrypt_CBC(ctx, temp_plaintext, iv, BLOCK_SIZE);
    memcpy(ciphertext_original, temp_plaintext, BLOCK_SIZE);  // Save the original ciphertext

    // Write the original plaintext, IV, and ciphertext to the file
    fprintf(file, "\nOriginal Plaintext: ");
    print_hex(file, plaintext, BLOCK_SIZE);
    fprintf(file, "\nOriginal IV: ");
    print_hex(file, iv, BLOCK_SIZE);
    fprintf(file, "\nOriginal Ciphertext: ");
    print_hex(file, ciphertext_original, BLOCK_SIZE);
    fprintf(file, "\n");

    // Modify one specific bit in the plaintext to check the avalanche effect
    uint8_t modified_plaintext[BLOCK_SIZE];
    memcpy(modified_plaintext, plaintext, BLOCK_SIZE);  // Copy original plaintext

    // Modify the specific bit in the plaintext (flip the bit passed as an argument)
    modified_plaintext[FLIP_BIT / 8] ^= (1 << (FLIP_BIT % 8)); // Flip the specific bit
    fprintf(file, "Flipping bit: %d\n", FLIP_BIT); // Show which bit is flipped

    // Encrypt the modified plaintext
    uint8_t temp_modified_plaintext[BLOCK_SIZE];
    memcpy(temp_modified_plaintext, modified_plaintext, BLOCK_SIZE); // Copy modified plaintext
    Blowfish_Encrypt_CBC(ctx, temp_modified_plaintext, iv, BLOCK_SIZE);
    memcpy(ciphertext_modified, temp_modified_plaintext, BLOCK_SIZE);  // Save the modified ciphertext

    // Calculate the bit differences between original and modified ciphertext (Hamming distance)
    int bit_difference = count_bit_difference(ciphertext_original, ciphertext_modified, BLOCK_SIZE);

    // Print the modified plaintext and ciphertext for this bit change
    fprintf(file, "Modified Plaintext (Flipped Bit %d): ", FLIP_BIT);
    print_hex(file, modified_plaintext, BLOCK_SIZE);
    fprintf(file, "\nModified Ciphertext: ");
    print_hex(file, ciphertext_modified, BLOCK_SIZE);
    fprintf(file, "\nHamming Distance: %d\n", bit_difference);

    // Compute the avalanche effect (percentage of bit changes)
    double avalanche_percentage = ((double)bit_difference / 64) * 100;
    fprintf(file, "Avalanche Effect: %.2f%%\n", avalanche_percentage);

    // Add the result to the total avalanche effect
    *total_avalanche += avalanche_percentage;
}

int main() {
    srand(time(NULL));

    BLOWFISH_CTX ctx;
    uint8_t key[BLOCK_SIZE] = "testkey";  // Blowfish 8-byte key (you can change the key size)
    double total_avalanche = 0.0;

    // Initialize Blowfish with the key
    Blowfish_Init(&ctx, key, BLOCK_SIZE);

    // Open the output file
    FILE *file = fopen("blowfish_avalanche_effect_results.txt", "w");
    if (file == NULL) {
        perror("Error opening file");
        return 1;
    }

    // Generate a fixed plaintext for all iterations
    uint8_t plaintext[BLOCK_SIZE];
    for (int i = 0; i < BLOCK_SIZE; i++) {
        plaintext[i] = rand() % 256;
    }

    // Run the avalanche test multiple iterations, flipping the same bit each time
    for (int i = 0; i < NUM_ITERATIONS; i++) {
        fprintf(file, "Iteration %d:\n", i + 1);

        // Perform the avalanche effect test (flip the same bit in each iteration)
        test_avalanche_effect(&ctx, key, plaintext, &total_avalanche, file);
    }

    // Calculate the final average avalanche effect
    double final_avg_avalanche = total_avalanche / NUM_ITERATIONS;
    fprintf(file, "\nFinal Average Avalanche Effect: %.2f%%\n", final_avg_avalanche);

    // Close the file
    fclose(file);

    return 0;
}


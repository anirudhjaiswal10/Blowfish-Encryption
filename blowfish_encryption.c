#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include "blowfish.h"

// Detect OS
#ifdef _WIN32  // Windows-specific includes
    #include <windows.h>
    double get_time_in_seconds() {
        LARGE_INTEGER frequency, start;
        QueryPerformanceFrequency(&frequency);
        QueryPerformanceCounter(&start);
        return (double)start.QuadPart / frequency.QuadPart;
    }
#else  // Linux/macOS
    #include <sys/time.h>
    double get_time_in_seconds() {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        return tv.tv_sec + tv.tv_usec / 1e6;  // Convert microseconds to seconds
    }
#endif

// Function to generate a random IV for CBC mode
void generate_random_iv(uint8_t *iv, size_t length) {
    for (size_t i = 0; i < length; i++) {
        iv[i] = rand() % 256;  // Random byte value between 0-255
    }
}

int main() {
    // Initialize Blowfish context
    BLOWFISH_CTX ctx;
    const char *key = "mysecretkey";
    int key_len = strlen(key);
    Blowfish_Init(&ctx, (uint8_t *)key, key_len);

    // Define test data sizes (8B, 64B, 1KB, 1MB)
    int data_sizes[] = {8, 64, 1024, 1048576};  

    for (int i = 0; i < 4; i++) {
        int data_len = data_sizes[i];
        unsigned char *data = (unsigned char *)malloc(data_len);
        if (!data) {
            printf("Memory allocation failed for %d bytes\n", data_len);
            return 1;
        }
        memset(data, 0, data_len); // Fill with dummy data

        // Ensure data length is a multiple of 8 (for Blowfish)
        if (data_len % 8 != 0) {
            data_len += 8 - (data_len % 8);
        }

        // Generate a random IV for CBC mode
        uint8_t iv[8];
        generate_random_iv(iv, 8);

        // Start high-precision timing
        double start = get_time_in_seconds();

        // Encrypt the data using CBC mode
        Blowfish_Encrypt_CBC(&ctx, data, iv, data_len);

        // End high-precision timing
        double end = get_time_in_seconds();
        double encryption_time = end - start;

        // Print results with higher precision
        printf("Data Size: %d bytes, Encryption Time: %.9f seconds\n", data_sizes[i], encryption_time);

        free(data);
    }

    return 0;
}


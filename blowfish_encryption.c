#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include "blowfish.h"
%
int main() {
    BLOWFISH_CTX ctx;
    const char *key = "mysecretkey";
    int key_len = strlen(key);
    Blowfish_Init(&ctx, (uint8_t *)key, key_len);

    // Test with different data sizes
    int data_sizes[] = {8, 64, 1024, 1048576}; // 8 bytes, 64 bytes, 1 KB, 1 MB
    for (int i = 0; i < 4; i++) {
        int data_len = data_sizes[i];
        unsigned char *data = (unsigned char *)malloc(data_len);
        memset(data, 0, data_len); // Fill with dummy data

        // Ensure data length is a multiple of 8
        if (data_len % 8 != 0) {
            data_len += 8 - (data_len % 8);
        }

        // Start timing
        clock_t start = clock();

        // Encrypt the data
        for (int j = 0; j < data_len; j += 8) {
            Blowfish_Encrypt(&ctx, (uint32_t *)(data + j), (uint32_t *)(data + j + 4));
        }

        // End timing
        clock_t end = clock();
        double encryption_time = (double)(end - start) / CLOCKS_PER_SEC;

        // Print results
        printf("Data Size: %d bytes, Encryption Time: %.6f seconds\n", data_sizes[i], encryption_time);

        free(data);
    }

    return 0;
}

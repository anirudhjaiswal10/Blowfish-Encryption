#include <stdio.h>
#include <stdint.h>
#include <string.h>

// Define number of rounds for Blowfish
#define N 16

typedef struct {
    uint32_t P[N + 2];   // P-array (18 values)
    uint32_t S[4][256];  // S-boxes (4 x 256 entries)
} BLOWFISH_CTX;

// Inline XOR-based F function (simplified for demonstration)
static inline uint32_t F(const BLOWFISH_CTX *ctx, uint32_t x) {
    uint8_t a = (x >> 24) & 0xFF;
    uint8_t b = (x >> 16) & 0xFF;
    uint8_t c = (x >> 8) & 0xFF;
    uint8_t d = x & 0xFF;
    return ((ctx->S[0][a] + ctx->S[1][b]) ^ ctx->S[2][c]) + ctx->S[3][d];
}

// Encrypt function with round-by-round logs
void blowfish_encrypt_with_logs(BLOWFISH_CTX *ctx, uint32_t *xl, uint32_t *xr) {
    uint32_t Xl = *xl;
    uint32_t Xr = *xr;

    printf("Initial Values:\n");
    printf("Round  0: Left = %08X, Right = %08X\n", Xl, Xr);

    // Feistel Network: 16 Rounds
    for (int i = 0; i < N; i++) {
        Xl ^= ctx->P[i];
        Xr ^= F(ctx, Xl);

        // Swap Left & Right
        uint32_t temp = Xl;
        Xl = Xr;
        Xr = temp;

        printf("Round %2d: Left = %08X, Right = %08X\n", i + 1, Xl, Xr);
    }

    // Undo final swap
    uint32_t temp = Xl;
    Xl = Xr;
    Xr = temp;

    // Final transformation
    Xr ^= ctx->P[N];
    Xl ^= ctx->P[N + 1];

    printf("Final Encrypted Values:\n");
    printf("Left  = %08X, Right = %08X\n", Xl, Xr);

    *xl = Xl;
    *xr = Xr;
}

// Initialize Blowfish context (Dummy values for demonstration)
void blowfish_init(BLOWFISH_CTX *ctx, const uint8_t *key, int key_len) {
    (void)key; // Suppress unused warning for now
    (void)key_len;

    // Dummy Initialization: Real implementation should use a key schedule
    for (int i = 0; i < N + 2; i++) ctx->P[i] = i;
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 256; j++)
            ctx->S[i][j] = (i * 256 + j);
}

int main() {
    BLOWFISH_CTX ctx;
    uint8_t key[8] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};

    // Initialize Blowfish with dummy key
    blowfish_init(&ctx, key, sizeof(key));

    // Input values (32-bit each)
    uint32_t Left = 0x01234567;
    uint32_t Right = 0x89ABCDEF;

    // Encrypt and log per round
    blowfish_encrypt_with_logs(&ctx, &Left, &Right);

    return 0;
}


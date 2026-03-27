#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef _WIN32
  #include <windows.h>
  #include <intrin.h>
#else
  static inline uint64_t __rdtsc(void) {
      uint32_t lo, hi;
      __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
      return ((uint64_t)hi << 32) | lo;
  }
#endif


#define RDTSC_THRESHOLD 200000ULL
static volatile uint32_t g_poison = 0;

static int rdtsc_check(void) {
    uint64_t t1 = __rdtsc();
    volatile uint32_t dummy = 0;
    for (int i = 0; i < 16; i++) dummy ^= (uint32_t)i * 0x1337;
    uint64_t t2 = __rdtsc();
    if ((t2 - t1) > RDTSC_THRESHOLD) {
        g_poison ^= 0xDEADBEEF;
        return 0;
    }
    return 1;
}

/* FNV-1a 32-bit */
static uint32_t fnv32(const char *s, size_t len) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; i++) {
        h ^= (uint8_t)s[i];
        h *= 16777619u;
    }
    return h;
}

static uint32_t rolling_hash(const char *input, size_t len, uint32_t key) {
    uint32_t state = key;
    for (size_t i = 0; i < len; i++) {
        uint8_t b = (uint8_t)input[i];
        if (g_poison) b ^= (uint8_t)(g_poison & 0xFF);
        state = ((state << 5) | (state >> 27)) ^ b;
        state += (state >> 3) ^ 0xA5A5A5A5;
        if (i == len / 2) rdtsc_check();
    }
    return state;
}

#define EXPECTED_HASH  0xD3C5431D

#ifdef COMPUTE_EXPECTED
static void compute_expected(void) {
    const char *shard1 = "HTB{c4r_k3ys";
    const char *shard2 = "sc4tt3r3d";
    uint32_t key = fnv32(shard1, strlen(shard1));
    printf("key           = 0x%08X\n", key);
    printf("EXPECTED_HASH = 0x%08X\n", rolling_hash(shard2, strlen(shard2), key));
    exit(0);
}
#endif

static void print_fake_shard(void) {
    uint8_t obf[] = { 0x77, 0x20, 0x70, 0x31, 0x32, 0x74, 0x3A, 0x7A, 0x2E };
    char fake[10] = {0};
    for (int i = 0; i < 9; i++)
        fake[i] = (char)(obf[i] ^ (uint8_t)(i + 0x42));
    printf("Correct! Shard 2: _%s\n", fake);
    for (int i = 0; i < 9; i++) fake[i] = 0;
}


static void store_real_shard(const char *shard1) {
    uint8_t pad[] = {
        0x18, 0x13, 0x5A, 0x2A, 0xD8, 0xCB, 0x41, 0xFF, 0x9A
    };

    uint32_t state = fnv32(shard1, strlen(shard1));

    char *real = (char *)calloc(10, 1);
    if (!real) return;

    for (int i = 0; i < 9; i++) {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        real[i] = (char)((state & 0xFF) ^ pad[i]);
    }

    volatile int hold = 0;
    for (int i = 0; i < 1000; i++) hold += i;
    (void)hold;

    for (int i = 0; i < 9; i++) real[i] = 0;
    free(real);
}

int main(void) {
#ifdef COMPUTE_EXPECTED
    compute_expected();
#endif

    rdtsc_check();

    printf("Enter shard 1: ");
    fflush(stdout);
    char shard1[64] = {0};
    if (!fgets(shard1, sizeof(shard1), stdin)) return 1;
    size_t l1 = strlen(shard1);
    if (l1 > 0 && shard1[l1-1] == '\n') shard1[--l1] = '\0';

    if (l1 != 12) { puts("Wrong."); return 1; }

    printf("Enter shard 2: ");
    fflush(stdout);
    char shard2[64] = {0};
    if (!fgets(shard2, sizeof(shard2), stdin)) return 1;
    size_t l2 = strlen(shard2);
    if (l2 > 0 && shard2[l2-1] == '\n') shard2[--l2] = '\0';

    if (l2 != 9) { puts("Wrong."); return 1; }

    rdtsc_check();

    uint32_t key = fnv32(shard1, l1);
    uint32_t h   = rolling_hash(shard2, l2, key);

    rdtsc_check();

    if (h == EXPECTED_HASH && g_poison == 0) {
        print_fake_shard();
        store_real_shard(shard1);
    } else {
        puts("Wrong.");
    }

    for (int i = 0; i < 64; i++) shard1[i] = 0;
    return 0;
}


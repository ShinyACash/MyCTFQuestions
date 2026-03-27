#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>


int __attribute__((noinline)) fake_check(int x) {
    int r = 0;
    for (int i = 0; i < x; i++) r ^= i * 0x13;
    return r & 0xFF;
}

uint8_t reverse_bits(uint8_t b) {
    uint8_t r = 0;
    for (int i = 0; i < 8; i++) {
        r = (r << 1) | (b & 1);
        b >>= 1;
    }
    return r;
}

uint8_t rotate_left(uint8_t b, int n) {
    n = n % 8;
    return ((b << n) | (b >> (8 - n))) & 0xFF;
}

int __attribute__((noinline)) validate_input(const char *s) {
    int sum = 0;
    while (*s) sum += *s++;
    if (fake_check(sum) == 0x42) return 1;
    return sum % 7;
}

void transform(const uint8_t *input, size_t len, uint8_t *output) {
    uint8_t tmp[256] = {0};

    for (size_t i = 0; i < len; i++)
        tmp[i] = reverse_bits(input[i]);

    if (validate_input((char*)input) == 0xDEAD) {
        for (size_t i = 0; i < len; i++) tmp[i] ^= 0xFF;
    }

    for (size_t i = 0; i < len; i++) {
        int r = (i % 5) + 1;
        tmp[i] = rotate_left(tmp[i], r);
    }

    for (size_t i = 0; i + 1 < len; i += 2) {
        uint8_t t = tmp[i];
        tmp[i] = tmp[i+1];
        tmp[i+1] = t;
    }

    memcpy(output, tmp, len);
}

static const char target_blob[] = "a824ed1218c832195fe9da9d23649d9935eb5fcac84de0d718c9669981ecfa9c"; // for the players

int main() {
    char input[256] = {0};
    uint8_t output[256] = {0};

    printf("Enter passphrase: ");
    if (!fgets(input, sizeof(input), stdin)) return 1;

    // strip newline
    size_t len = strlen(input);
    if (len > 0 && input[len-1] == '\n') input[--len] = 0;

    transform((uint8_t*)input, len, output);

    printf("Output: ");
    for (size_t i = 0; i < len; i++) printf("%02x", output[i]);
    printf("\n");

    char hex[512] = {0};
    for (size_t i = 0; i < len; i++) sprintf(hex + i*2, "%02x", output[i]);
    if (strcmp(hex, target_blob) == 0)
        printf("Correct.\n");

    return 0;
}

/* 

author: 
hasbiyama (@3xploitZero)
github.com/hasbiyama

[HARD-TO-REVERSE] 

> gcc -o challenge4 challenge4.c -O3 -s -fvisibility=hidden -fdata-sections -ffunction-sections -Wl,--gc-sections -fno-stack-protector -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-ident -fomit-frame-pointer -static

[SECURE] 

> gcc -o challenge4 challenge4.c -O3 -s -fvisibility=hidden -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie -Wl,-z,relro,-z,now -static

[DUMP]

objdump -M intel -j .text -d ./challenge4

*/

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <errno.h>

#define BLOCK_SIZE 8
#define SECURE_ZERO(ptr, size) memset(ptr, 0, size)
#define SECURE_FREE(ptr, size) do { \
    if (ptr) { \
        SECURE_ZERO(ptr, size); \
        munlock(ptr, size); \
        free(ptr); \
        ptr = NULL; \
    } \
} while (0)

uint8_t sbox[256];
uint8_t inv_sbox[256];

void init_sboxes() {
    for (int i = 0; i < 256; i++) {
        sbox[i] = (i * 73 + 29) % 256;
        inv_sbox[sbox[i]] = i;
    }
}

const uint8_t ENC_P1_A[2] = {0x18, 0x08};
const uint8_t ENC_P1_B[2] = {0x0D, 0x00};
const uint8_t ENC_P1_C[2] = {0x00, 0x00};
const uint8_t ENC_P1_D[3] = {0x00, 0x00, 0x00};

const uint8_t ENC_P2_A[2] = {0x00, 0x00};
const uint8_t ENC_P2_B[2] = {0x00, 0x00};
const uint8_t ENC_P2_C[2] = {0x00, 0x00};
const uint8_t ENC_P2_D[2] = {0x00, 0x00};
const uint8_t ENC_P2_E[3] = {0x00, 0x00, 0x00};

const uint8_t KEY_P1_A[2] = {0x24, 0xEC};
const uint8_t KEY_P1_B[2] = {0xC1, 0x55};
const uint8_t KEY_P1_C[2] = {0x60, 0x1E};
const uint8_t KEY_P1_D[2] = {0xBA, 0x00};

const uint8_t KEY_P2_A[2] = {0x2A, 0xED};
const uint8_t KEY_P2_B[2] = {0x6F, 0xE8};
const uint8_t KEY_P2_C[2] = {0xA2, 0xE3};
const uint8_t KEY_P2_D[2] = {0x2E, 0x96};

const uint8_t KEY_P3_A[2] = {0xBF, 0x8F};
const uint8_t KEY_P3_B[2] = {0xF2, 0xE8};
const uint8_t KEY_P3_C[2] = {0xD3, 0xAD};
const uint8_t KEY_P3_D[2] = {0x66, 0x4C};

const uint8_t XOR_P1[2] = {0x10, 0x20};
const uint8_t XOR_P2[2] = {0x30, 0x40};
const uint8_t XOR_P3[2] = {0x50, 0x60};
const uint8_t XOR_P4[2] = {0x70, 0x80};

#define ENC_TOTAL_LEN 22
#define KEY_TOTAL_LEN 24
#define TOTAL_LEN ((ENC_TOTAL_LEN < KEY_TOTAL_LEN) ? ENC_TOTAL_LEN : KEY_TOTAL_LEN)

uint8_t* secure_alloc(size_t size) {
    uint8_t *ptr = calloc(1, size);
    if (!ptr || mlock(ptr, size) != 0) {
        // perror("secure_alloc");  // Removed string
        free(ptr);
        return NULL;
    }
    return ptr;
}

void secure_free_all(uint8_t **ptrs, size_t *sizes, size_t count) {
    for (size_t i = 0; i < count; i++) {
        SECURE_FREE(ptrs[i], sizes[i]);
    }
}

int secure_compare(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

void append(uint8_t *dest, const uint8_t *src, size_t *offset, size_t len) {
    memcpy(dest + *offset, src, len);
    *offset += len;
}

void inverse_substitute(uint8_t *block) {
    for (int i = 0; i < BLOCK_SIZE; i++) {
        block[i] = inv_sbox[block[i]];
    }
}

void permute(uint8_t *block) {
    for (int i = 0; i < (BLOCK_SIZE >> 1); i++) {
        uint8_t temp = block[i];
        block[i] = block[BLOCK_SIZE - 1 - i];
        block[BLOCK_SIZE - 1 - i] = temp;
    }
}

void mixKey(uint8_t *block, uint8_t *key) {
    for (int i = 0; i < BLOCK_SIZE; i++) {
        block[i] ^= key[i];
    }
}

void key_xor_key_decrypt(uint8_t *data, int len, uint8_t *key) {
    for (int i = 0; i < len; i += BLOCK_SIZE) {
        mixKey(&data[i], key);
        permute(&data[i]);
        inverse_substitute(&data[i]);
    }
}

void secure_obfuscate(uint8_t *data, size_t len) {
    const uint8_t xor_key = 0xAA;
    for (size_t i = 0; i < len; i++) {
        data[i] ^= xor_key + (i % 16);
        data[i] = ((data[i] << 4) | (data[i] >> 4)) & 0xFF;
    }
    for (size_t i = 0; i < (len >> 1); i++) {
        uint8_t tmp = data[i];
        data[i] = data[len - 1 - i];
        data[len - 1 - i] = tmp;
    }
}

void secure_deobfuscate(uint8_t *data, size_t len) {
    for (size_t i = 0; i < (len >> 1); i++) {
        uint8_t tmp = data[i];
        data[i] = data[len - 1 - i];
        data[len - 1 - i] = tmp;
    }
    for (size_t i = 0; i < len; i++) {
        data[i] = ((data[i] >> 4) | (data[i] << 4)) & 0xFF;
        data[i] ^= 0xAA + (i % 16);
    }
}

int check_key(const char *input) {
    if (strnlen(input, TOTAL_LEN + 1) != TOTAL_LEN) return 0;

    uint8_t *enc = secure_alloc(TOTAL_LEN);
    uint8_t *key = secure_alloc(KEY_TOTAL_LEN);
    uint8_t *decrypted = secure_alloc(TOTAL_LEN);
    uint8_t key_xor_key[BLOCK_SIZE];

    if (!enc || !key || !decrypted) {
        uint8_t *ptrs[] = {enc, key, decrypted};
        size_t sizes[] = {TOTAL_LEN, KEY_TOTAL_LEN, TOTAL_LEN};
        secure_free_all(ptrs, sizes, 3);
        return 0;
    }

    size_t off = 0;

    append(enc, ENC_P1_A, &off, sizeof(ENC_P1_A));
    append(enc, ENC_P1_B, &off, sizeof(ENC_P1_B));
    append(enc, ENC_P1_C, &off, sizeof(ENC_P1_C));
    append(enc, ENC_P1_D, &off, sizeof(ENC_P1_D));
    append(enc, ENC_P2_A, &off, sizeof(ENC_P2_A));
    append(enc, ENC_P2_B, &off, sizeof(ENC_P2_B));
    append(enc, ENC_P2_C, &off, sizeof(ENC_P2_C));
    append(enc, ENC_P2_D, &off, sizeof(ENC_P2_D));
    append(enc, ENC_P2_E, &off, sizeof(ENC_P2_E));

    off = 0;
    append(key, KEY_P1_A, &off, sizeof(KEY_P1_A));
    append(key, KEY_P1_B, &off, sizeof(KEY_P1_B));
    append(key, KEY_P1_C, &off, sizeof(KEY_P1_C));
    append(key, KEY_P1_D, &off, sizeof(KEY_P1_D));
    append(key, KEY_P2_A, &off, sizeof(KEY_P2_A));
    append(key, KEY_P2_B, &off, sizeof(KEY_P2_B));
    append(key, KEY_P2_C, &off, sizeof(KEY_P2_C));
    append(key, KEY_P2_D, &off, sizeof(KEY_P2_D));
    append(key, KEY_P3_A, &off, sizeof(KEY_P3_A));
    append(key, KEY_P3_B, &off, sizeof(KEY_P3_B));
    append(key, KEY_P3_C, &off, sizeof(KEY_P3_C));
    append(key, KEY_P3_D, &off, sizeof(KEY_P3_D));

    off = 0;
    append(key_xor_key, XOR_P1, &off, sizeof(XOR_P1));
    append(key_xor_key, XOR_P2, &off, sizeof(XOR_P2));
    append(key_xor_key, XOR_P3, &off, sizeof(XOR_P3));
    append(key_xor_key, XOR_P4, &off, sizeof(XOR_P4));

    key_xor_key_decrypt(key, KEY_TOTAL_LEN, key_xor_key);

    secure_obfuscate(enc, TOTAL_LEN);
    secure_obfuscate(key, TOTAL_LEN);
    secure_deobfuscate(enc, TOTAL_LEN);
    secure_deobfuscate(key, TOTAL_LEN);

    for (size_t i = 0; i < TOTAL_LEN; i++) {
        decrypted[i] = enc[i] ^ key[i];
    }

    int result = secure_compare(decrypted, (const uint8_t *)input, TOTAL_LEN);

    uint8_t *ptrs[] = {enc, key, decrypted};
    size_t sizes[] = {TOTAL_LEN, KEY_TOTAL_LEN, TOTAL_LEN};
    secure_free_all(ptrs, sizes, 3);

    return result;
}

int main(int argc, char *argv[]) {
    init_sboxes();

    if (argc < 2) {
        // printf("Usage: %s <key_string>\n", argv[0]);  // Removed string
        return 1;
    }

    return check_key(argv[1]) ? (/* printf("Correct key!\n"), */ 0)
                              : (/* printf("Wrong key!\n"), */ 1);
}

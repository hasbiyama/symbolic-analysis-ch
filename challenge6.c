/* 

author: 
hasbiyama (@3xploitZero)
github.com/hasbiyama

[HARD-TO-REVERSE] 

> gcc -o challenge4 challenge6.c -O3 -s -fvisibility=hidden -fdata-sections -ffunction-sections -Wl,--gc-sections -fno-stack-protector -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-ident -fomit-frame-pointer -static

[SECURE] 

> gcc -o challenge4 challenge6.c -O3 -s -fvisibility=hidden -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie -Wl,-z,relro,-z,now

[DUMP]

objdump -M intel -j .text -d ./challenge6

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

#define ENC_TOTAL_LEN 22
#define KEY_TOTAL_LEN 24
#define TOTAL_LEN ((ENC_TOTAL_LEN < KEY_TOTAL_LEN) ? ENC_TOTAL_LEN : KEY_TOTAL_LEN)

typedef struct {
    const uint8_t *data;
    size_t len;
} ConstBlock;

uint8_t sbox[256];
uint8_t inv_sbox[256];

void init_sboxes() {
    for (int i = 0; i < 256; i++) {
        sbox[i] = (i * 73 + 29) % 256;
        inv_sbox[sbox[i]] = i;
    }
}

// Encryption constants
static const uint8_t enc_p1_a[] = {0x18, 0x08};
static const uint8_t enc_p1_b[] = {0x0D, 0x00};
static const uint8_t enc_p1_c[] = {0x00, 0x00};
static const uint8_t enc_p1_d[] = {0x00, 0x00, 0x00};
static const uint8_t enc_p2_a[] = {0x00, 0x00};
static const uint8_t enc_p2_b[] = {0x00, 0x00};
static const uint8_t enc_p2_c[] = {0x00, 0x00};
static const uint8_t enc_p2_d[] = {0x00, 0x00};
static const uint8_t enc_p2_e[] = {0x00, 0x00, 0x00};

static const ConstBlock ENC_PARTS[] = {
    {enc_p1_a, sizeof(enc_p1_a)},
    {enc_p1_b, sizeof(enc_p1_b)},
    {enc_p1_c, sizeof(enc_p1_c)},
    {enc_p1_d, sizeof(enc_p1_d)},
    {enc_p2_a, sizeof(enc_p2_a)},
    {enc_p2_b, sizeof(enc_p2_b)},
    {enc_p2_c, sizeof(enc_p2_c)},
    {enc_p2_d, sizeof(enc_p2_d)},
    {enc_p2_e, sizeof(enc_p2_e)},
};

// Key constants
static const uint8_t key_p1_a[] = {0x24, 0xEC};
static const uint8_t key_p1_b[] = {0xC1, 0x55};
static const uint8_t key_p1_c[] = {0x60, 0x1E};
static const uint8_t key_p1_d[] = {0xBA, 0x00};
static const uint8_t key_p2_a[] = {0x2A, 0xED};
static const uint8_t key_p2_b[] = {0x6F, 0xE8};
static const uint8_t key_p2_c[] = {0xA2, 0xE3};
static const uint8_t key_p2_d[] = {0x2E, 0x96};
static const uint8_t key_p3_a[] = {0xBF, 0x8F};
static const uint8_t key_p3_b[] = {0xF2, 0xE8};
static const uint8_t key_p3_c[] = {0xD3, 0xAD};
static const uint8_t key_p3_d[] = {0x66, 0x4C};

static const ConstBlock KEY_PARTS[] = {
    {key_p1_a, sizeof(key_p1_a)},
    {key_p1_b, sizeof(key_p1_b)},
    {key_p1_c, sizeof(key_p1_c)},
    {key_p1_d, sizeof(key_p1_d)},
    {key_p2_a, sizeof(key_p2_a)},
    {key_p2_b, sizeof(key_p2_b)},
    {key_p2_c, sizeof(key_p2_c)},
    {key_p2_d, sizeof(key_p2_d)},
    {key_p3_a, sizeof(key_p3_a)},
    {key_p3_b, sizeof(key_p3_b)},
    {key_p3_c, sizeof(key_p3_c)},
    {key_p3_d, sizeof(key_p3_d)},
};

// XOR key constants
static const uint8_t xor_p1[] = {0x10, 0x20};
static const uint8_t xor_p2[] = {0x30, 0x40};
static const uint8_t xor_p3[] = {0x50, 0x60};
static const uint8_t xor_p4[] = {0x70, 0x80};

static const ConstBlock XOR_PARTS[] = {
    {xor_p1, sizeof(xor_p1)},
    {xor_p2, sizeof(xor_p2)},
    {xor_p3, sizeof(xor_p3)},
    {xor_p4, sizeof(xor_p4)},
};

uint8_t* secure_alloc(size_t size) {
    uint8_t *ptr = calloc(1, size);
    if (!ptr || mlock(ptr, size) != 0) {
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
    for (size_t i = 0; i < sizeof(ENC_PARTS)/sizeof(ConstBlock); i++) {
        append(enc, ENC_PARTS[i].data, &off, ENC_PARTS[i].len);
    }

    off = 0;
    for (size_t i = 0; i < sizeof(KEY_PARTS)/sizeof(ConstBlock); i++) {
        append(key, KEY_PARTS[i].data, &off, KEY_PARTS[i].len);
    }

    off = 0;
    for (size_t i = 0; i < sizeof(XOR_PARTS)/sizeof(ConstBlock); i++) {
        append(key_xor_key, XOR_PARTS[i].data, &off, XOR_PARTS[i].len);
    }

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
        return 1;
    }

    return check_key(argv[1]) ? 0 : 1;
}

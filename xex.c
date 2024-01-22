#include "ds.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>

#define IV_SIZE 16

static void xor (uint8_t *s1, uint8_t *s2, size_t len) {
    while (len--) {
        *s1++ ^= *s2++;
    }
}

void aes_xex_decrypt_sector (AES_KEY *key, uint64_t sector, void *data) {
    uint8_t pre_iv[IV_SIZE], next_iv[IV_SIZE];
    union {
        uint8_t iv[IV_SIZE];
        struct {
            uint64_t sector, zero;
        } elements;
    } iv;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    iv.elements.sector = sector;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    iv.elements.sector = ntohll (sector);
#else
#error "Unsupported endianness."
#endif
    iv.elements.zero = 0;
    AES_decrypt (iv.iv, pre_iv, key);
    for (uint8_t *p = data ; p != data + SECTOR_SIZE ; p += IV_SIZE) {
        xor (p, pre_iv, IV_SIZE);
        memcpy (next_iv, p, IV_SIZE);
        AES_decrypt (p, p, key);
        xor (p, iv.iv, IV_SIZE);
        memcpy (iv.iv, next_iv, IV_SIZE);
    }
}

int aes_xex_decrypt_image (AES_KEY *key, uint64_t start_sector, FILE *fp_in, FILE *fp_out) {
    int return_code = 0;
    void *buffer = malloc (BUFFER_SIZE);
    if (buffer == NULL ) {
        return 0;
    }
    for (uint64_t sector = start_sector ; ; ) {
        size_t sectors = fread (buffer, SECTOR_SIZE, BUFFER_SECTORS, fp_in);
        if (sectors == 0) {
            if (errno == 0) {
                return_code = 1;
                break;
            } else {
                break;
            }
        }
        uint8_t *p = buffer;
        for (uint64_t i = sector ; i != sector + sectors ; i++, p += SECTOR_SIZE) {
            aes_xex_decrypt_sector (key, i, p);
        }
        if (fwrite (buffer, SECTOR_SIZE, sectors, fp_out) != sectors) {
            break;
        }
        sector += sectors;
    }
    free (buffer);
    return return_code;
}

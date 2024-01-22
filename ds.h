#pragma once

#include <stdint.h>
#include <stdio.h>
#include <openssl/aes.h>

struct ds_kernel_key {
    const char *kernel_version;
    uint8_t key[16];
};

extern const struct ds_kernel_key keys[];
extern const struct ds_kernel_key *keys_end;
extern const int keys_count;

#define SECTOR_SIZE (512)
#define BUFFER_SECTORS (16 * 1024)
#define BUFFER_SIZE (BUFFER_SECTORS * SECTOR_SIZE)

void aes_xex_decrypt_sector (AES_KEY *key, uint64_t sector, void *data);
int aes_xex_decrypt_image (AES_KEY *key, uint64_t start_sector, FILE *fp_in, FILE *fp_out);

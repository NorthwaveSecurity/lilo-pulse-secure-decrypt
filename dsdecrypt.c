#include "ds.h"

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <openssl/crypto.h>

static int all_zeroes (uint8_t *buffer, size_t len) {
    for (uint8_t *p = buffer ; p != buffer + len ; p++) {
        if (*p != 0) {
            return 0;
        }
    }
    return 1;
}
static const struct ds_kernel_key* ivanti_probe_key (uint8_t *buffer) {
    for (const struct ds_kernel_key *p = keys ; p != keys_end ; p++) {
        uint8_t decrypt_buffer[SECTOR_SIZE];
        memcpy (decrypt_buffer, buffer, SECTOR_SIZE);
        AES_KEY key;
        AES_set_decrypt_key (p->key, 128, &key);
        aes_xex_decrypt_sector (&key, 0, decrypt_buffer);

        if (all_zeroes (decrypt_buffer, SECTOR_SIZE)) {
            memcpy (buffer, decrypt_buffer, SECTOR_SIZE);
            return p;
        }
    }
    return NULL;
}
struct options {
    const struct ds_kernel_key *key;
    int force, verbose;
    FILE *input, *output;
};
int decrypt (struct options *options) {
    uint64_t start_sector = 0;
    if (options->key == NULL) {
        if (options->verbose) {
            fprintf (stderr, "No key specified, probing.\n");
        }
        uint8_t buffer[SECTOR_SIZE];
        if (fread (buffer, SECTOR_SIZE, 1, options->input) != 1) {
            fprintf (stderr, "Short read.\n");
            return 0;
        }
        const struct ds_kernel_key *key = ivanti_probe_key (buffer);
        if (key == NULL) {
            fprintf (stderr, "No matching key found.\n");
            return 0;
        }
        if (fwrite (buffer, SECTOR_SIZE, 1, options->output) != 1) {
            fprintf (stderr, "Short write.\n");
            return 0;
        }
        options->key = key;
        start_sector = 1;
    }
    if (options->verbose) {
        fprintf (stderr, "Probe done key=%s start_sector=%lld\n", options->key->kernel_version, start_sector);
    }
    AES_KEY key;
    AES_set_decrypt_key (options->key->key, 128, &key);
    return aes_xex_decrypt_image (&key, start_sector, options->input, options->output);
}
static FILE *parse_input_filename (const char *filename) {
    if (strcmp (filename, "-") == 0) {
        return stdin;
    } else {
        return fopen (filename, "rb");
    }
}
FILE *parse_output_filename (const char *filename) {
    if (strcmp (filename, "-") == 0) {
        return stdout;
    } else {
        return fopen (filename, "wb");
    }
}
void usage (void) {
    fprintf (stderr,
            "usage: [-k key] [-v] <input-filename> <output-filename>\n"
            "\tKey\tKernel version\n"
            );
    for (int i = 0 ; i != keys_count ; i++) {
        const struct ds_kernel_key *key = &keys[i];
        fprintf (stderr, "\t%2d\t%s\n", i, key->kernel_version);
    }
    exit (-1);
}
int parse_options (int argc, char *argv[], struct options *options) {
    static const char *optstring = "k:v";

    options->key = NULL;
    options->force = 0;
    options->verbose = 0;
    options->input = NULL;
    options->output = NULL;

    for (int ch = getopt (argc, argv, optstring) ; ch != -1 ; ch = getopt (argc, argv, optstring)) {
        switch (ch) {
            case 'k':
                {
                    int key = atoi (optarg);
                    if (key < 0 || key > keys_count) {
                        fprintf (stderr, "Invalid key index\n");
                        usage ();
                    }
                    options->key = &keys[key];
                }
                break;

            case 'f':
                options->force = 1;
                break;

            case 'v':
                options->verbose = 1;
                break;

            case 'h':
            default:
                usage ();
                return 0;
        }
    }
    printf("argc - optind = %d\n", argc - optind);
    switch (argc - optind) {
        case 2:
            options->input = parse_input_filename (argv[optind]);
            options->output = parse_output_filename (argv[optind + 1]);
            break;
        case 1:
            options->input = parse_input_filename (argv[optind]);
            options->output = stdout;
            break;
        case 0:
            options->input = stdin;
            options->output = stdout;
            break;
        default:
            return 0;
    }
    return 1;
}
int main (int argc, char *argv[]) {
    OPENSSL_init_crypto (0, NULL);
    struct options options;

    if (parse_options (argc, argv, &options) == 0) {
        exit (-1);
    }
    decrypt (&options);
    fclose (options.input);
    fclose (options.output);
}

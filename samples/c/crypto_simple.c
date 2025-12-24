/**
 * crypto_simple.c - Simple XOR encryption for reverse engineering practice
 *
 * Demonstrates:
 * - Bitwise operations (EOR instruction)
 * - Loop patterns
 * - Memory manipulation
 * - Simple "obfuscation" patterns
 *
 * Perfect for learning to identify crypto/encoding in binaries
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* XOR encrypt/decrypt with single-byte key */
void xor_cipher(unsigned char *data, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

/* XOR with multi-byte key (repeating) */
void xor_cipher_multi(unsigned char *data, size_t len,
                      const unsigned char *key, size_t key_len) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key[i % key_len];
    }
}

/* Simple ROT13-like substitution */
void rot13(char *str) {
    while (*str) {
        if (*str >= 'a' && *str <= 'z') {
            *str = 'a' + ((*str - 'a' + 13) % 26);
        } else if (*str >= 'A' && *str <= 'Z') {
            *str = 'A' + ((*str - 'A' + 13) % 26);
        }
        str++;
    }
}

/* Caesar cipher with configurable shift */
void caesar(char *str, int shift) {
    shift = ((shift % 26) + 26) % 26;  /* Normalize shift */
    while (*str) {
        if (*str >= 'a' && *str <= 'z') {
            *str = 'a' + ((*str - 'a' + shift) % 26);
        } else if (*str >= 'A' && *str <= 'Z') {
            *str = 'A' + ((*str - 'A' + shift) % 26);
        }
        str++;
    }
}

/* Simple hash function (djb2) - commonly seen in binaries */
unsigned long djb2_hash(const char *str) {
    unsigned long hash = 5381;
    int c;

    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;  /* hash * 33 + c */
    }

    return hash;
}

/* Print hex dump */
void hexdump(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    if (len % 16 != 0) printf("\n");
}

int main(void) {
    /* XOR demo */
    printf("=== XOR Cipher Demo ===\n");
    unsigned char message[] = "Secret message!";
    size_t len = strlen((char*)message);
    unsigned char key = 0x42;

    printf("Original: %s\n", message);
    printf("Hex: "); hexdump(message, len);

    xor_cipher(message, len, key);
    printf("\nEncrypted (key=0x%02X):\n", key);
    printf("Hex: "); hexdump(message, len);

    xor_cipher(message, len, key);  /* Decrypt (XOR is its own inverse) */
    printf("\nDecrypted: %s\n", message);

    /* Multi-byte XOR */
    printf("\n=== Multi-byte XOR Demo ===\n");
    unsigned char message2[] = "Another secret!";
    size_t len2 = strlen((char*)message2);
    unsigned char multi_key[] = {0xDE, 0xAD, 0xBE, 0xEF};

    printf("Original: %s\n", message2);
    xor_cipher_multi(message2, len2, multi_key, 4);
    printf("Encrypted: "); hexdump(message2, len2);
    xor_cipher_multi(message2, len2, multi_key, 4);
    printf("Decrypted: %s\n", message2);

    /* ROT13 demo */
    printf("\n=== ROT13 Demo ===\n");
    char text[] = "Hello World";
    printf("Original: %s\n", text);
    rot13(text);
    printf("ROT13: %s\n", text);
    rot13(text);  /* ROT13 twice = original */
    printf("Double ROT13: %s\n", text);

    /* Hash demo */
    printf("\n=== Hash Demo (djb2) ===\n");
    const char *strings[] = {"hello", "world", "test", "password"};
    for (int i = 0; i < 4; i++) {
        printf("djb2(\"%s\") = 0x%08lx\n", strings[i], djb2_hash(strings[i]));
    }

    return 0;
}

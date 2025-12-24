/**
 * vulnerable.c - Buffer overflow demonstration for ARM reverse engineering
 *
 * WARNING: This code is intentionally vulnerable for educational purposes.
 * DO NOT use in production!
 *
 * Demonstrates:
 * - Stack buffer overflow vulnerability
 * - Unsafe string functions (strcpy, gets)
 * - Control flow hijacking potential
 * - Stack layout analysis
 *
 * Compile with: -fno-stack-protector -z execstack (for demonstration)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Victim function with small buffer */
void vulnerable_function(const char *input) {
    char buffer[64];  /* Small buffer - easily overflowed */

    /* VULNERABLE: No bounds checking! */
    strcpy(buffer, input);

    printf("You entered: %s\n", buffer);
}

/* Function that should never be called normally */
void secret_function(void) {
    printf("=== SECRET FUNCTION REACHED ===\n");
    printf("Congratulations! You've exploited the vulnerability.\n");
}

/* Another function for ROP practice */
void gadget_helper(int a, int b) {
    printf("Helper called with: %d, %d\n", a, b);
}

int main(int argc, char *argv[]) {
    printf("Buffer Overflow Demo\n");
    printf("====================\n");
    printf("secret_function is at: %p\n", (void*)secret_function);
    printf("gadget_helper is at: %p\n", (void*)gadget_helper);
    printf("\n");

    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        printf("Try overflowing the 64-byte buffer!\n");
        return 1;
    }

    printf("Calling vulnerable_function with your input...\n\n");
    vulnerable_function(argv[1]);

    printf("\nProgram completed normally.\n");
    return 0;
}

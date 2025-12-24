/**
 * hello.c - Simple hello world for ARM reverse engineering practice
 *
 * Demonstrates:
 * - Basic program structure
 * - libc function calls (puts)
 * - String literals in .rodata
 */

#include <stdio.h>

int main(void) {
    puts("Hello, ARM World!");
    return 0;
}

/**
 * fibonacci.c - Recursive Fibonacci for ARM reverse engineering practice
 *
 * Demonstrates:
 * - Recursive function calls (BL/RET patterns)
 * - Stack frame management (STP/LDP for callee-saved registers)
 * - Conditional branches (CBZ, B.LE)
 * - Arithmetic operations (ADD, SUB)
 */

#include <stdio.h>

/* Recursive Fibonacci - shows call stack usage */
int fibonacci(int n) {
    if (n <= 1) {
        return n;
    }
    return fibonacci(n - 1) + fibonacci(n - 2);
}

/* Iterative version for comparison */
int fibonacci_iterative(int n) {
    if (n <= 1) return n;

    int prev = 0;
    int curr = 1;

    for (int i = 2; i <= n; i++) {
        int next = prev + curr;
        prev = curr;
        curr = next;
    }

    return curr;
}

int main(void) {
    int n = 10;

    printf("Fibonacci(%d) recursive = %d\n", n, fibonacci(n));
    printf("Fibonacci(%d) iterative = %d\n", n, fibonacci_iterative(n));

    return 0;
}

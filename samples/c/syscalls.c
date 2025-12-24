/**
 * syscalls.c - Direct syscall examples for ARM reverse engineering practice
 *
 * Demonstrates:
 * - Direct syscall invocation (SVC #0)
 * - Register-based argument passing (x0-x7)
 * - Syscall numbers in x8
 * - No libc dependency for syscall functions
 *
 * ARM64 Linux syscall ABI:
 * - x8: syscall number
 * - x0-x5: arguments
 * - x0: return value
 */

#include <unistd.h>
#include <sys/syscall.h>

/* Write string using raw syscall */
static long sys_write(int fd, const char *buf, unsigned long count) {
    register long x0 __asm__("x0") = fd;
    register const char *x1 __asm__("x1") = buf;
    register unsigned long x2 __asm__("x2") = count;
    register long x8 __asm__("x8") = SYS_write;

    __asm__ volatile (
        "svc #0"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x8)
        : "memory"
    );

    return x0;
}

/* Exit using raw syscall */
static void sys_exit(int code) {
    register long x0 __asm__("x0") = code;
    register long x8 __asm__("x8") = SYS_exit;

    __asm__ volatile (
        "svc #0"
        :
        : "r"(x0), "r"(x8)
    );

    __builtin_unreachable();
}

/* Get process ID using raw syscall */
static long sys_getpid(void) {
    register long x0 __asm__("x0");
    register long x8 __asm__("x8") = SYS_getpid;

    __asm__ volatile (
        "svc #0"
        : "=r"(x0)
        : "r"(x8)
    );

    return x0;
}

/* Minimal strlen without libc */
static unsigned long my_strlen(const char *s) {
    const char *p = s;
    while (*p) p++;
    return p - s;
}

/* Entry point - using _start to avoid libc */
void _start(void) {
    const char msg[] = "Hello from raw syscalls!\n";
    const char pid_msg[] = "PID: ";

    sys_write(1, msg, my_strlen(msg));
    sys_write(1, pid_msg, my_strlen(pid_msg));

    /* Simple number printing */
    long pid = sys_getpid();
    char buf[16];
    int i = 0;

    if (pid == 0) {
        buf[i++] = '0';
    } else {
        int j = 0;
        while (pid > 0) {
            buf[i++] = '0' + (pid % 10);
            pid /= 10;
        }
        /* Reverse */
        for (j = 0; j < i / 2; j++) {
            char t = buf[j];
            buf[j] = buf[i - 1 - j];
            buf[i - 1 - j] = t;
        }
    }
    buf[i++] = '\n';

    sys_write(1, buf, i);

    sys_exit(0);
}

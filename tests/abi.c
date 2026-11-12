/* ABI coverage helpers: stack arguments, floating point arguments and stubs. */
#include <stddef.h>

/* 7 arguments: the 7th one is passed on the stack (x86-64 SysV). */
long sum7(long a, long b, long c, long d, long e, long f, long g) {
    return a + b + c + d + e + f + g;
}

/* 10 arguments: 4 of them are passed on the stack (x86-64 SysV). */
long sum10(long a, long b, long c, long d, long e, long f,
           long g, long h, long i, long j) {
    return a + b + c + d + e + f + g + h + i + j;
}

/* Floating point arguments go into the SIMD registers. */
double add_double(double a, double b) { return a + b; }

/* Mixed integer/floating point arguments. */
double mix_args(long a, double b, long c, double d) {
    return (double)a + b + (double)c + d;
}

/* Used to check that a call can be stubbed out. */
int multiply(int a, int b) { return a * b; }
int call_multiply(int a, int b) { return multiply(a, b); }

int main(void) { return 0; }

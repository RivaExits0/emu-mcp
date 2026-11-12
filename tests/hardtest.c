#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

/* recursion */
long factorial(long n) {
    if (n <= 1) return 1;
    return n * factorial(n - 1);
}

/* indirect call via function pointer */
typedef long (*op_fn)(long, long);
long apply_op(op_fn f, long a, long b) { return f(a, b); }
long mul(long a, long b) { return a * b; }
long add2(long a, long b) { return a + b; }

/* many args (>6, stack args) */
long sum8(long a,long b,long c,long d,long e,long f,long g,long h) {
    return a+b+c+d+e+f+g+h;
}

/* struct pass by pointer */
typedef struct { long x; long y; } Pt;
long dist2(const Pt* p) { return p->x*p->x + p->y*p->y; }

/* memory aliasing / in-place */
void reverse_bytes(unsigned char* buf, size_t n) {
    for (size_t i = 0; i < n/2; i++) {
        unsigned char t = buf[i];
        buf[i] = buf[n-1-i];
        buf[n-1-i] = t;
    }
}

/* nested calls */
long nested(long x) {
    long a = factorial(5);
    long b = sum8(1,2,3,4,5,6,7,8);
    return x + a + b;
}

/* calls libc strcmp */
int check_str(const char* s) {
    return strcmp(s, "SECRET") == 0;
}

/* floating point */
double fadd(double a, double b) { return a + b; }
double fsquare(double x) { return x * x; }

/* global data access */
static int g_counter = 0;
int inc_global(void) { return ++g_counter; }
int get_global(void) { return g_counter; }

/* loop with early exit */
int find_byte(const unsigned char* buf, size_t n, unsigned char target) {
    for (size_t i = 0; i < n; i++) {
        if (buf[i] == target) return (int)i;
    }
    return -1;
}

int main(void){ return 0; }

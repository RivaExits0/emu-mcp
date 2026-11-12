#include <stdint.h>
#include <stddef.h>

uint32_t crc32_simple(const unsigned char *data, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            if (crc & 1) crc = (crc >> 1) ^ 0xEDB88320u;
            else crc >>= 1;
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

void xor_decrypt(unsigned char *buf, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) buf[i] ^= key;
}

long add(long a, long b) { return a + b; }

int main(void) { return 0; }

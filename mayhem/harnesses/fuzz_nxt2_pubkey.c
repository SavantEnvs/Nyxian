/* Fuzz the NXT2 vendor public-key file reader (Surface/trust/signing.c,
 * trust_nxt2_public_key_read): header {magic "N2PK", version, name_len, key_len}, vendor name,
 * DER SubjectPublicKeyInfo that must be an EC key. The input is the key file. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <LindChain/ProcEnvironment/Surface/trust/signing.h>

int memfd_create(const char *name, unsigned int flags);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int fd = memfd_create("nyx-pubkey", 0);
    if(fd < 0) return 0;
    size_t off = 0;
    while(off < size)
    {
        ssize_t n = write(fd, data + off, size - off);
        if(n <= 0) { close(fd); return 0; }
        off += (size_t)n;
    }
    char path[64];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);  /* the API takes a path */
    nxt2_vendor_key_t key;
    if(trust_nxt2_public_key_read(path, &key) == KERN_SUCCESS)
    {
        free(key.vendor_name);
        free(key.public_key);
    }
    close(fd);
    return 0;
}

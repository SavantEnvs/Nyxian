/* Fuzz the NXT2 trust-blob reader (Surface/trust/signing.c, trust_nxt2_read_fd): it parses the
 * trailer Nyxian appends to every binary it signs — [blob][u32 len]["NXT2"], blob = packed header
 * {cdhash, nonce, plist_len, plist} + footer {mac_len, mac[72]} — and turns the plist into the
 * process's entitlements. This is the successor of the code fixed by upstream 369a6c21
 * (entitlement_mach_verify mac_len OOB). Built in the nxtool configuration (__NXTOOL=1, HOST_ENV=1),
 * which reads the same trailer without the iOS-only signature check. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <LindChain/ProcEnvironment/Surface/trust/signing.h>

/* glibc symbol; declared here because nyx_pre.h is force-included before _GNU_SOURCE could apply */
int memfd_create(const char *name, unsigned int flags);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int fd = memfd_create("nyx-nxt2", 0);
    if(fd < 0) return 0;
    size_t off = 0;
    while(off < size)
    {
        ssize_t n = write(fd, data + off, size - off);
        if(n <= 0) { close(fd); return 0; }
        off += (size_t)n;
    }
    ksurface_nxt2_t result;
    if(trust_nxt2_read_fd(fd, &result) == KERN_SUCCESS && result.entitlements != NULL)
        CFRelease(result.entitlements);
    close(fd);
    return 0;
}

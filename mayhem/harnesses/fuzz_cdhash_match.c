/* Fuzz the cdhash comparison ksurface uses to bind an NXT2 trust blob to its Mach-O image:
 * CDHashMatchesCodeDirectoryFD() mmaps the file, computes its cdhash and compares it with the
 * expected one (Surface/trust/apple.c). The input is the image file; the expected cdhash is a
 * fixed value (the comparison result does not change which code runs). */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <CoreFoundation/CoreFoundation.h>

/* glibc symbol; declared here because nyx_pre.h is force-included before _GNU_SOURCE could apply */
int memfd_create(const char *name, unsigned int flags);
kern_return_t CDHashMatchesCodeDirectoryFD(int fd, const uint8_t expected_cdhash[USER_FSIGNATURES_CDHASH_LEN]);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int fd = memfd_create("nyx-image", 0);
    if(fd < 0) return 0;
    size_t off = 0;
    while(off < size)
    {
        ssize_t n = write(fd, data + off, size - off);
        if(n <= 0) { close(fd); return 0; }
        off += (size_t)n;
    }
    static const uint8_t expected[USER_FSIGNATURES_CDHASH_LEN] = {0};
    CDHashMatchesCodeDirectoryFD(fd, expected);
    close(fd);
    return 0;
}

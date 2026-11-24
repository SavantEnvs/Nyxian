/* Fuzz ksurface's Apple code-signature reader: CDHashOfMachO() walks a thin/fat Mach-O,
 * finds LC_CODE_SIGNATURE, indexes the CS SuperBlob and hashes the best CodeDirectory.
 * ksurface runs it on every executable a guest process loads (Surface/trust/cdhash.c). */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <LindChain/ProcEnvironment/Surface/trust/cdhash.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* exact-size heap copy so ASan sees any read past the image */
    uint8_t *buf = malloc(size ? size : 1);
    if(buf == NULL) return 0;
    memcpy(buf, data, size);
    uint8_t out[USER_FSIGNATURES_CDHASH_LEN];
    CDHashOfMachO(buf, size, out);
    free(buf);
    return 0;
}

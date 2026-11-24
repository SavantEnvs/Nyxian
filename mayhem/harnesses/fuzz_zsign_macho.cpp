// Fuzz the vendored zsign Mach-O slice parser (LiveContainer/ZSign/archo.cpp) that Nyxian runs on
// every binary of a user-built app before re-signing it: ZArchO::Init walks the header and load
// commands (segments, LC_CODE_SIGNATURE, encryption info, embedded Info.plist), and PrintInfo
// decodes the existing code signature (SuperBlob, CodeDirectory, requirements, entitlements).
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include "archo.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // ZMachO::OpenFile (macho.cpp), the only caller, hands a thin image to ZArchO::Init only when
    // its first word is one of the four Mach-O magics, with the file size as a uint32_t.
    if(size < sizeof(uint32_t) || size > 0xffffffffu) return -1;
    uint32_t magic;
    memcpy(&magic, data, sizeof(magic));
    if(magic != MH_MAGIC && magic != MH_CIGAM && magic != MH_MAGIC_64 && magic != MH_CIGAM_64) return -1;
    uint8_t *buf = (uint8_t *)malloc(size);
    if(buf == NULL) return 0;
    memcpy(buf, data, size);
    ZArchO archo;
    if(archo.Init(buf, (uint32_t)size))
    {
        archo.IsExecute();
        archo.PrintInfo();
    }
    free(buf);
    return 0;
}

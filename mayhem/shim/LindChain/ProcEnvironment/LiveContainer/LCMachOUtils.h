/* Stand-in for LiveContainer/LCMachOUtils.h (Objective-C): the C half trust/signing.c uses — the
 * LCMachO mapping struct and its FD map/unmap pair (implemented in mayhem/shim/cf_stub.c). */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <mach-o/loader.h>
typedef struct {
    int fd;
    bool ro;
    char *path;
    void *map;
    size_t size;
    struct mach_header_64 *header;
} LCMachO;
LCMachO *LCMapMachOFromFDRO(int fd);
void LCUnmapMachO(LCMachO *machO);

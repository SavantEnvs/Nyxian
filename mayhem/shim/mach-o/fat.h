#pragma once
#include <stdint.h>
#define FAT_MAGIC 0xcafebabe
#define FAT_CIGAM 0xbebafeca
#define FAT_MAGIC_64 0xcafebabf
#define FAT_CIGAM_64 0xbfbafeca
struct fat_header { uint32_t magic, nfat_arch; };
struct fat_arch { int cputype, cpusubtype; uint32_t offset, size, align; };
struct fat_arch_64 { int cputype, cpusubtype; uint64_t offset, size; uint32_t align, reserved; };

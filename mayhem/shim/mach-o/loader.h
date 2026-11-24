#pragma once
#include <stdint.h>
#define MH_MAGIC_64 0xfeedfacf
#define LC_CODE_SIGNATURE 0x1d
#define LC_SEGMENT_64 0x19
typedef int cpu_type_t; typedef int cpu_subtype_t;
struct mach_header_64 { uint32_t magic; cpu_type_t cputype; cpu_subtype_t cpusubtype; uint32_t filetype, ncmds, sizeofcmds, flags, reserved; };
struct load_command { uint32_t cmd, cmdsize; };
struct linkedit_data_command { uint32_t cmd, cmdsize, dataoff, datasize; };

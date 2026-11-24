/* Linux stand-ins for the Darwin headers/macros the lifted Nyxian C parsers expect.
 * Force-included (-include) into every Nyxian TU the harnesses compile. */
#ifndef NYX_PRE_H
#define NYX_PRE_H
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <endian.h>
#define USER_FSIGNATURES_CDHASH_LEN 20
#define CPU_TYPE_ARM64 0x0100000c
#define OSSwapBigToHostInt32(x) be32toh(x)
#define OSSwapBigToHostInt64(x) be64toh(x)
#define OSSwapInt32(x) __builtin_bswap32(x)
#define OSSwapInt64(x) __builtin_bswap64(x)
typedef int kern_return_t;
#define KERN_SUCCESS 0
#define KERN_INVALID_ARGUMENT 4
#define KERN_FAILURE 5
#define KERN_NO_SPACE 3
#define KERN_RESOURCE_SHORTAGE 6
#define KERN_DENIED 53
/* the code runs on arm64 iOS, whose VM page is 16 KiB */
#ifndef PAGE_SIZE
#define PAGE_SIZE 16384
#endif
#endif

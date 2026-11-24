#pragma once
/* Minimal CoreFoundation stand-in for the Nyxian trust code built on Linux: the types and the handful
 * of CF calls trust/signing.c, trust/entitlement.h and trust/apple.c use. Implemented in
 * mayhem/shim/cf_stub.c (opaque CFData/CFDictionary objects; see there for the plist stand-in). */
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
/* the Darwin CoreFoundation umbrella pulls these in transitively */
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>

#define CF_ENUM(_type, _name) _type _name; enum
#define CF_OPTIONS(_type, _name) _type _name; enum
#define CFSTR(s) ((CFStringRef)(s))

typedef unsigned char UInt8;
typedef unsigned char Boolean;
typedef long CFIndex;
typedef unsigned long CFOptionFlags;
typedef unsigned long CFTypeID;
typedef int32_t OSStatus;
typedef const void *CFTypeRef;
typedef const void *CFPropertyListRef;
typedef const struct __CFAllocator *CFAllocatorRef;
typedef const struct __CFString *CFStringRef;
typedef const struct __CFDictionary *CFDictionaryRef;
typedef struct __CFDictionary *CFMutableDictionaryRef;
typedef const struct __CFData *CFDataRef;
typedef const struct __CFURL *CFURLRef;
typedef struct __CFError *CFErrorRef;
typedef CFIndex CFPropertyListFormat;
enum { kCFPropertyListOpenStepFormat = 1, kCFPropertyListXMLFormat_v1_0 = 100, kCFPropertyListBinaryFormat_v1_0 = 200 };
enum { kCFPropertyListImmutable = 0, kCFPropertyListMutableContainers = 1 };
#define kCFAllocatorDefault ((CFAllocatorRef)NULL)

CFDataRef CFDataCreate(CFAllocatorRef a, const UInt8 *bytes, CFIndex length);
CFIndex CFDataGetLength(CFDataRef d);
const UInt8 *CFDataGetBytePtr(CFDataRef d);
void CFRelease(CFTypeRef cf);
CFTypeID CFGetTypeID(CFTypeRef cf);
CFTypeID CFDictionaryGetTypeID(void);
CFTypeID CFDataGetTypeID(void);
CFPropertyListRef CFPropertyListCreateWithData(CFAllocatorRef a, CFDataRef data, CFOptionFlags options,
                                               CFPropertyListFormat *format, CFErrorRef *error);
CFDataRef CFPropertyListCreateData(CFAllocatorRef a, CFPropertyListRef pl, CFPropertyListFormat format,
                                   CFOptionFlags options, CFErrorRef *error);
CFStringRef CFErrorCopyDescription(CFErrorRef err);
#define CF_TYPED_ENUM

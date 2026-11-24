/* Linux stand-ins for the CoreFoundation calls and the LCMachO FD mapping used by trust/signing.c.
 * CF objects are heap blocks with a type tag. CFPropertyListCreateWithData stands in for Apple's
 * plist parser: it copies the bytes it is given (so ASan checks the whole range the caller passes)
 * and returns a dictionary for any non-empty input, an error for an empty one. */
#include <CoreFoundation/CoreFoundation.h>
#include <LindChain/ProcEnvironment/LiveContainer/LCMachOUtils.h>
#include <sys/mman.h>
#include <sys/stat.h>

enum { T_DATA = 1, T_DICT = 2 };
typedef struct { CFTypeID type; CFIndex len; UInt8 bytes[]; } cfobj_t;

static cfobj_t *mk(CFTypeID type, const UInt8 *bytes, CFIndex len)
{
    if(len < 0) return NULL;
    cfobj_t *o = malloc(sizeof(*o) + (size_t)len);
    if(o == NULL) return NULL;
    o->type = type; o->len = len;
    if(len) memcpy(o->bytes, bytes, (size_t)len);
    return o;
}

CFDataRef CFDataCreate(CFAllocatorRef a, const UInt8 *bytes, CFIndex length) { (void)a; return (CFDataRef)mk(T_DATA, bytes, length); }
CFIndex CFDataGetLength(CFDataRef d) { return ((const cfobj_t *)d)->len; }
const UInt8 *CFDataGetBytePtr(CFDataRef d) { return ((const cfobj_t *)d)->bytes; }
void CFRelease(CFTypeRef cf) { free((void *)cf); }
CFTypeID CFGetTypeID(CFTypeRef cf) { return ((const cfobj_t *)cf)->type; }
CFTypeID CFDictionaryGetTypeID(void) { return T_DICT; }
CFTypeID CFDataGetTypeID(void) { return T_DATA; }

CFPropertyListRef CFPropertyListCreateWithData(CFAllocatorRef a, CFDataRef data, CFOptionFlags options,
                                               CFPropertyListFormat *format, CFErrorRef *error)
{
    (void)a; (void)options;
    if(error) *error = NULL;
    if(format) *format = kCFPropertyListXMLFormat_v1_0;
    const cfobj_t *d = (const cfobj_t *)data;
    if(d == NULL || d->len == 0) return NULL;
    return mk(T_DICT, d->bytes, d->len);
}

CFDataRef CFPropertyListCreateData(CFAllocatorRef a, CFPropertyListRef pl, CFPropertyListFormat format,
                                   CFOptionFlags options, CFErrorRef *error)
{
    (void)a; (void)format; (void)options;
    if(error) *error = NULL;
    const cfobj_t *o = (const cfobj_t *)pl;
    return o ? (CFDataRef)mk(T_DATA, o->bytes, o->len) : NULL;
}

CFStringRef CFErrorCopyDescription(CFErrorRef err) { (void)err; return NULL; }

LCMachO *LCMapMachOFromFDRO(int fd)
{
    if(fd < 0) return NULL;
    struct stat st;
    if(fstat(fd, &st) != 0 || st.st_size <= 0) { close(fd); return NULL; }
    void *map = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if(map == MAP_FAILED) { close(fd); return NULL; }
    LCMachO *m = calloc(1, sizeof(*m));
    if(m == NULL) { munmap(map, (size_t)st.st_size); close(fd); return NULL; }
    m->fd = fd; m->ro = true; m->map = map; m->size = (size_t)st.st_size; m->header = map;
    return m;
}

void LCUnmapMachO(LCMachO *m)
{
    munmap(m->map, m->size);
    close(m->fd);
    free(m->path);
    free(m);
}

#include <openssl/sha.h>
#include <CommonCrypto/CommonCrypto.h>
unsigned char *CC_SHA1(const void *d, CC_LONG l, unsigned char *md) { return SHA1(d, l, md); }
unsigned char *CC_SHA256(const void *d, CC_LONG l, unsigned char *md) { return SHA256(d, l, md); }
unsigned char *CC_SHA384(const void *d, CC_LONG l, unsigned char *md) { return SHA384(d, l, md); }

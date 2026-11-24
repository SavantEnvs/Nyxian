// Known-answer driver for mayhem/test.sh: runs the same Nyxian parsers the fuzz targets reach
// and prints their results, which test.sh diffs against golden values.
//   nyx_selftest cdhash <file>   -> hex cdhash, or "none"
//   nyx_selftest json <file>     -> parsed document re-serialised as compact JSON
//   nyx_selftest plist <file>    -> parsed plist re-serialised as compact JSON
//   nyx_selftest nxt2 <file>     -> trailer verdict + entitlements plist length
//   nyx_selftest pubkey <file>   -> vendor name + DER key length
//   nyx_selftest radix           -> walk of a fixed insert/remove sequence
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <fstream>
#include <sstream>
#include "json.h"

extern "C" {
bool CDHashOfMachO(const uint8_t *base, size_t size, uint8_t out[20]);
#include <LindChain/ProcEnvironment/Surface/libkern/radix/radix.h>
#include <LindChain/ProcEnvironment/Surface/trust/signing.h>
}

static std::string slurp(const char *path)
{
    std::ifstream f(path, std::ios::binary);
    if(!f) { fprintf(stderr, "cannot open %s\n", path); exit(2); }
    std::stringstream ss; ss << f.rdbuf(); return ss.str();
}

static void walk_print(uint64_t ident, void *value, void *)
{
    printf("%llx=%lu\n", (unsigned long long)ident, (unsigned long)(uintptr_t)value);
}

int main(int argc, char **argv)
{
    if(argc < 2) return 2;
    std::string mode = argv[1];
    if(mode == "cdhash" && argc == 3)
    {
        std::string d = slurp(argv[2]);
        uint8_t out[20];
        if(!CDHashOfMachO((const uint8_t *)d.data(), d.size(), out)) { printf("none\n"); return 0; }
        for(int i = 0; i < 20; i++) printf("%02x", out[i]);
        printf("\n");
        return 0;
    }
    if((mode == "json" || mode == "plist") && argc == 3)
    {
        std::string d = slurp(argv[2]);
        jvalue v; std::string err;
        bool ok = mode == "json" ? v.read(d, &err) : v.read_plist(d, &err);
        if(!ok) { printf("error\n"); return 0; }
        std::string out; v.write(out);
        printf("%s\n", out.c_str());
        return 0;
    }
    if(mode == "nxt2" && argc == 3)
    {
        ksurface_nxt2_t r;
        kern_return_t kr = trust_nxt2_read(argv[2], &r);
        printf("kr=%d valid=%d cdhash_valid=%d signed=%d plist=%ld\n", kr, r.isValid, r.isCdHashValid, r.isSigned,
               r.entitlements ? (long)CFDataGetLength((CFDataRef)r.entitlements) : -1L);
        return 0;
    }
    if(mode == "pubkey" && argc == 3)
    {
        nxt2_vendor_key_t k;
        kern_return_t kr = trust_nxt2_public_key_read(argv[2], &k);
        printf("kr=%d vendor=%s keylen=%zu\n", kr, k.vendor_name ? k.vendor_name : "-", k.public_key_len);
        return 0;
    }
    if(mode == "radix")
    {
        radix_tree_t t = { NULL };
        const uint64_t ids[] = { 1, 2, 300, 0x10000, 0xdeadbeefcafe, 2, 77 };
        for(size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); i++)
            radix_insert(&t, ids[i], (void *)(uintptr_t)(i + 1));
        radix_remove(&t, 300);
        radix_remove(&t, 77);
        printf("lookup2=%lu lookup300=%lu\n", (unsigned long)(uintptr_t)radix_lookup(&t, 2),
               (unsigned long)(uintptr_t)radix_lookup(&t, 300));
        radix_walk(&t, walk_print, NULL);
        return 0;
    }
    return 2;
}

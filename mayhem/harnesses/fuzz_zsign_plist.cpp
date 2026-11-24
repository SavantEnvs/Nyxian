// Fuzz the vendored zsign property-list reader (LiveContainer/ZSign/common/json.cpp: XML plist
// via jpreader, binary plist via the bplist path) used on Info.plist, entitlements and
// provisioning profiles while signing user-built apps; then re-serialise the result.
#include <stdint.h>
#include <stddef.h>
#include <string>
#include "json.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // the std::string overload, as zsign's callers use it (Info.plist / entitlements data)
    std::string doc(reinterpret_cast<const char *>(data), size);
    jvalue v;
    std::string err;
    bool is_binary = false;
    if(v.read_plist(doc, &err, &is_binary))
    {
        std::string out;
        v.write_plist(out);
        v.write(out);
    }
    return 0;
}

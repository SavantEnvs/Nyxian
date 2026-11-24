// Fuzz the vendored zsign JSON reader (LiveContainer/ZSign/common/json.cpp, jreader) that
// Nyxian uses while signing user-built apps, then re-serialise what it parsed.
#include <stdint.h>
#include <stddef.h>
#include <string>
#include "json.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    std::string doc(reinterpret_cast<const char *>(data), size);
    jvalue v;
    std::string err;
    if(v.read(doc, &err))
    {
        std::string out;
        v.write(out);
        v.style_write(out);
    }
    return 0;
}

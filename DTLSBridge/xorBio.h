#pragma once

#include <openssl/bio.h>

inline constexpr const uint64_t NRS_XOR_MAGIC = 0x1BC257E12C598C63;

namespace xorFilter
{
    int xorFilterWrite(BIO* b, const char* data, int dlen);
    int xorFilterRead(BIO* b, char* data, int outl);

    int xorFilterCreate(BIO* b);
    int xorFilterDestroy(BIO* b);
    int xorFilterGets(BIO* b, char* buf, int size);
    int xorFilterPuts(BIO* b, const char* str);
    void xorData(char* data, size_t length, uint64_t key);
}
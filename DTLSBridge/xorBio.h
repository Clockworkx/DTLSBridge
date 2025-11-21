#pragma once

#include <openssl/bio.h>

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
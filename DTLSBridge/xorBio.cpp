#include "xorBio.h"

#ifdef LOGGING
#include <iostream>
#endif
#include <openssl/err.h>


void xorFilter::xorData(char* data, size_t length, uint64_t key)
{
	int bufferPosition = 0;
	for (; bufferPosition + 8 <= length; bufferPosition += 8)
	{
		*reinterpret_cast<uint64_t*>(data + bufferPosition) ^= key;
	}

	for (; bufferPosition < length; ++bufferPosition)
	{
		data[bufferPosition] ^= ((const char*)&key)[bufferPosition % 8];
	}
}


int xorFilter::xorFilterWrite(BIO* b, const char* data, int dlen)
{
#ifdef LOGGING
	std::cout << "xorFilterWrite called with data length: " << dlen << "\n";
#endif
	xorData(const_cast<char*>(data), dlen, NRS_XOR_MAGIC);
	return BIO_write(BIO_next(b), data, dlen);
}

int xorFilter::xorFilterRead(BIO* b, char* data, int dlen)
{

	int bytesReceived = BIO_read(BIO_next(b), data, dlen);

	if (bytesReceived <= 0) {
#ifdef LOGGING
		std::cout << "received <= 0" << bytesReceived;
#endif
		return bytesReceived;
	}
#ifdef LOGGING
	std::cout << "xorFilterRead called with data length: " << bytesReceived << "\n";
#endif

	xorData(data, bytesReceived, NRS_XOR_MAGIC);
	return bytesReceived;
}

int xorFilter::xorFilterCreate(BIO* b)
{
	BIO_set_init(b, 1);
	BIO_set_data(b, nullptr);
#ifdef LOGGING
	std::cout << "xorFilterCreate called\n";
#endif
	return 1;
}

int xorFilter::xorFilterDestroy(BIO* b)
{
	// No dynamic data to free, but required for completeness
#ifdef LOGGING
	std::cout << "xorFilterDestroy called\n";
#endif
	return 1;
}


int xorFilter::xorFilterGets(BIO* b, char* buf, int size)
{
	// Not supported for this filter
#ifdef LOGGING
	std::cout << "xorFilterGets called, not supported for this filter\n";
#endif
	return -1;
}

int xorFilter::xorFilterPuts(BIO* b, const char* str)
{
	// Not supported for this filter
#ifdef LOGGING
	std::cout << "xorFilterPuts called, not supported for this filter\n";
#endif
	return -1;
}




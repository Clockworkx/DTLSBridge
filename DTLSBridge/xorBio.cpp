#include "xorBio.hpp"

#include <cstdint>

inline constexpr const uint64_t NRS_XOR_MAGIC = 0x1BC257E12C598C63;

void xorFilter::xorData(char* data, size_t length)
{
	int bufferPosition = 0;
	for (; bufferPosition + 8 <= length; bufferPosition += 8)
	{
		*reinterpret_cast<uint64_t*>(data + bufferPosition) ^= NRS_XOR_MAGIC;
	}

	for (; bufferPosition < length; ++bufferPosition)
	{
		data[bufferPosition] ^= ((const char*)&NRS_XOR_MAGIC)[bufferPosition % 8];
	}
}

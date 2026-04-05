#pragma once

#include <cstdint>
#include <cstddef>

#ifdef DTLSBRIDGE_EXPORTS
	#ifdef _WIN32
		#define DTLSBRIDGE_API __declspec(dllexport)
	#else
		#define DTLSBRIDGE_API __attribute__((visibility("default")))
	#endif
#else
	#define DTLSBRIDGE_API __declspec(dllimport)
#endif

extern "C" {
	// inputData may be modified. Returns true if input data could successfully be decoded as DTLS traffic.
	DTLSBRIDGE_API bool ReadData(uint8_t* inputData, size_t inputDataLength, uint8_t pendingSendBuffer[4096], size_t* pendingSendLength, uint8_t decryptedDataBuffer[4096], size_t* decryptedDataLength, const char* endpoint);
	DTLSBRIDGE_API void WriteData(const uint8_t* rawData, size_t rawDataLength, uint8_t encryptedData[4096], size_t* encryptedDataLength, const char* endpoint);
	DTLSBRIDGE_API void init();
}
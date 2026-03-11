#pragma once

#include "pch.h"


#ifdef DTLSBRIDGE_EXPORTS
#define  DTLSBRIDGE_API __declspec(dllexport)
#else
#define DTLSBRIDGE_API __declspec(dllimport)
#endif

extern "C" {
	DTLSBRIDGE_API void ReadData(uint8_t* inputData, size_t inputDataLength, uint8_t* pendingSendBuffer, size_t* pendingSendLength, uint8_t decryptedDataBuffer[4096], size_t* decryptedDataLength, const char* endpoint);
	DTLSBRIDGE_API void WriteData(uint8_t* rawData, size_t rawDataLength, uint8_t* encryptedData, size_t* encryptedDataLength, const char* endpoint);
	DTLSBRIDGE_API void init();
}
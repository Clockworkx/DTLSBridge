#include "pch.h"

#include <iostream>
#include "DTLS.h"

#include <unordered_map>
#include <vector>
#include <openssl/ssl.h>

#include "xorBio.h"
#include <openssl/err.h>
#include <openssl/bio.h>

#include "DtlsRecord.h"

#include <WinSock2.h>
#include <WS2tcpip.h>

#include "Globals.h"


int generateCookie(SSL* ssl, unsigned char* cookie, unsigned int* cookie_len)
{
	memcpy(cookie, "cookie", 6);
	*cookie_len = 6;

	return 1;
}

int verifyCookie(SSL* ssl, const unsigned char* cookie, unsigned int cookie_len)
{
	return 1;
}

int verify(int ok, X509_STORE_CTX* ctx)
{
	return 1;
}

unsigned int psk_server_callback(SSL* ssl, const char* identity, unsigned char* psk, unsigned int max_psk_len)
{
	std::vector<unsigned char> pskS = { 0x4F, 0x74, 0x57, 0x72, 0x4C, 0x66, 0x77, 0x56, 0x6A, 0x6D, 0x59, 0x6D, 0x45, 0x6B };

	if (identity != nullptr)
	{
		std::cout << "PSK identity: " << identity << "\n";
	}

	if (strcmp(identity, "c4ad847c") == 0)
	{
		memcpy(psk, pskS.data(), pskS.size());
		return static_cast<unsigned int>(pskS.size());
	}
	return 0;
}

struct DTLSClient
{
	SSL* ssl;
	BIO* rMemBio;
	BIO* wMemBio;
	bool hasExchangedCookie;
};


void init()
{
	SSL_CTX* ctx = SSL_CTX_new(DTLS_server_method());
	SSL_CTX_set_cookie_generate_cb(ctx, generateCookie);
	SSL_CTX_set_cookie_verify_cb(ctx, verifyCookie);
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, verify);
	SSL_CTX_set_cipher_list(ctx, "HIGH");
	SSL_CTX_set_psk_server_callback(ctx, psk_server_callback);
	Globals::ctx = ctx;
}

std::unordered_map<std::string, DTLSClient> clients;

void printError(SSL* ssl, int result)
{
	int ssl_error = SSL_get_error(ssl, result);
	std::cout << "SSL error code: " << ssl_error << "\n";

	//unsigned long e = ERR_get_error();

	//char buf[256];
	//ERR_error_string_n(e, buf, sizeof(buf));
	//printf("Error: %s\n", buf);


	//const char* reason = ERR_reason_error_string(e);

	switch (ssl_error) {
	case SSL_ERROR_WANT_READ:
		std::cout << "WANT_READ\n";
		break;
	case SSL_ERROR_WANT_WRITE:
		std::cout << "WANT_WRITE\n";
		break;
	case SSL_ERROR_ZERO_RETURN:
		std::cout << "CLOSED\n";
		break;
	case SSL_ERROR_SYSCALL:
		std::cout << "SYSCALL\n";  // check errno
		break;
	case SSL_ERROR_SSL:
		std::cout << "SSL_ERROR_SSL\n"; // now call ERR_get_error()
		break;
	default:
		std::cout << "UNKNOWN\n";
	}
}

void getPendingData(BIO* writeBio, uint8_t* target, size_t* pendingBytesWritten)
{
	int pendingSize = BIO_pending(writeBio);
	std::cout << "ReadData() write bio pending size: " << pendingSize << "\n";

	if (pendingSize <= 0)
	{
		std::cout << "Tried reading pending write data but no pending data in bio" << "\n";
		*pendingBytesWritten = 0;
		return;
	}

	uint8_t pendingData[4096];
	int bytesRead = BIO_read(writeBio, pendingData, pendingSize);

	std::cout << "ReadData() bytes read from write bio:" << bytesRead << "\n";

	for (int i = 0; i < bytesRead; i++)
	{
		std::cout << std::hex << (int)pendingData[i] << " ";
	}

	xorFilter::xorData(reinterpret_cast<char*>(pendingData), pendingSize, 0x1BC257E12C598C63);

	std::memcpy(target, pendingData, bytesRead);
	*pendingBytesWritten = bytesRead;
}



void ReadData(uint8_t* inputData, size_t inputDataLength, uint8_t* pendingSendBuffer, size_t* pendingSendLength, uint8_t* decrpytedDataBuffer, size_t* decryptedDataLength, const char* endpoint)
{
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();

	std::cout << "ReadData() input data length: " << inputDataLength << "\n";
	//for (int i = 0; i < inputDataLength; i++)
//{
//	std::cout << std::hex << (int)inputData[i] << " ";
//}


	if (inputDataLength <= 0)
	{
		std::cout << "ReadData() input data length is zero or negative" << "\n";
		*decryptedDataLength = 0;
		return;
	}

	std::vector<uint8_t> input(inputData, inputData + inputDataLength);
	if (!isDTLSRecord(input))
	{
		xorFilter::xorData(reinterpret_cast<char*>(inputData), inputDataLength, 0x1BC257E12C598C63);
	}

	isDTLSRecord(input);

	auto client = clients.find(std::string{ endpoint });
	if (client == clients.end())
	{
		std::cout << "ReadData() endpoint not found, checking for cookie" << "\n";

		*decryptedDataLength = 0;

		SSL* ssl = SSL_new(Globals::ctx);

		BIO* rMemBio = BIO_new(BIO_s_mem());
		BIO* wMemBio = BIO_new(BIO_s_mem());

		SSL_set_bio(ssl, rMemBio, wMemBio);
		SSL_set_accept_state(ssl);

		int bioWritten = BIO_write(rMemBio, inputData, inputDataLength);
		std::cout << "ReadData() bytes written to read bio: " << bioWritten << "\n";

		BIO_ADDR* peer = BIO_ADDR_new();
		int listenRet = DTLSv1_listen(ssl, peer);
		BIO_ADDR_free(peer);

		if (listenRet < 1)
		{
			std::cout << "DTLSv1_listen returned < 1" << "\n";

			if (listenRet < 0)
			{
				std::cout << "Fatal Error in DTLSv1_listen" << "\n";
				printError(ssl, listenRet);
				return;
			}

			std::cout << "DTLSv1_listen returned HelloVerifyRequest" << "\n";
			getPendingData(wMemBio, pendingSendBuffer, pendingSendLength);

			SSL_free(ssl);
			return;
		}

		std::cout << "DTLSv1_listen succeeded, cookie verified" << "\n";
		auto it = clients.emplace(std::string{ endpoint }, DTLSClient{ ssl, rMemBio, wMemBio, true });
		DTLSClient& dtlsClient = it.first->second;

		bool isHandshakeFinished = SSL_is_init_finished(dtlsClient.ssl);

		if (!isHandshakeFinished)
		{
			int result = SSL_do_handshake(dtlsClient.ssl);

			std::cout << "do_handshake_result: " << result << "\n";

			if (result < 1)
			{
				printError(dtlsClient.ssl, result);
			}

		}
		else
		{
			std::cout << "Handshake already finished after DTLSv1_listen should not happen" << "\n";
		}

		getPendingData(dtlsClient.wMemBio, pendingSendBuffer, pendingSendLength);
		return;
	}

	DTLSClient& dtlsClient = client->second;

	int bioWritten = BIO_write(dtlsClient.rMemBio, inputData, inputDataLength);
	std::cout << "ReadData() bytes written to read bio: " << bioWritten << "\n";

	bool isHandshakeFinished = SSL_is_init_finished(dtlsClient.ssl);

	if (!isHandshakeFinished)
	{
		int result = SSL_do_handshake(dtlsClient.ssl);

		std::cout << "do_handshake_result: " << result << "\n";

		if (result < 1)
		{
			printError(dtlsClient.ssl, result);
		}

	}

	if (isHandshakeFinished)
	{
		std::cout << "ReadData() handshake finished" << "\n";
		uint8_t decryptedData[4096];
		int bytesRead = SSL_read(dtlsClient.ssl, decryptedData, sizeof(decryptedData));

		std::cout << "ssl_read decrypted bytes read: " << bytesRead << "\n";

		if (bytesRead > 0)
		{
			for (int i = 0; i < bytesRead; i++)
			{
				std::cout << std::hex << (int)decryptedData[i] << " ";
			}
			std::cout << "\n";
			std::memcpy(decrpytedDataBuffer, decryptedData, bytesRead);
			*decryptedDataLength = bytesRead;
			getPendingData(dtlsClient.wMemBio, pendingSendBuffer, pendingSendLength);
			return;
		}
		std::cout << "ssl_read bytesRead <= 0" << "\n";
		printError(dtlsClient.ssl, bytesRead);

		std::cout << "checking for close notify" << "\n";
		const int shutdownMask = SSL_get_shutdown(dtlsClient.ssl);

		const bool receivedCloseNotify = (shutdownMask & SSL_RECEIVED_SHUTDOWN) != 0;

		if (receivedCloseNotify) {
			std::cout << "DTLS received close-notify. Deleting client\n";
			getPendingData(dtlsClient.wMemBio, pendingSendBuffer, pendingSendLength);

			clients.erase({ endpoint });
			return;
		}

	//	DTLSPlaintext record;
	//	if (!parseDTLSPlaintext(inputData, inputDataLength, record))
	//	{
	//		std::cout << "Failed to parse DTLSPlaintext record" << "\n";
	//		return;
	//	}

	//	switch (record.type)
	//	{
	//	case handshake:
	//	{

	//	}
	//	case application_data:
	//	{

	//	}
	//	default:
	//	{

	//		std::cout << "Received DTLS record of unhandled type: " << static_cast<int>(record.type) << "\n";
	//		return;
	//	}

	//	}

	//	if (record.type == application_data)
	//	{
	//		std::cout << "ReadData() received application data DTLS record" << "\n";
	//	}
	//	else
	//	{
	//		std::cout << "Parsed DTLS record details:" << "\n";
	//		std::cout << "record.type: " << static_cast<int>(record.type) << "\n";
	//		std::cout << "record.length: " << record.length << "\n";
	//		std::cout << "record.fragment size: " << record.fragment.size() << "\n";
	//		std::cout << "\n";

	//		std::cout << "ReadData() received non-application data DTLS record of type: " << record.type << "\n";
	//		if (isClientHello(record))
	//		{
	//			std::cout << "ReadData() received ClientHello message" << "\n";
	//		}
	//	}
	//}
	//else
	//{
	//	std::cout << "ReadData() failed to parse DTLS record" << "\n";
	//}

	}


	getPendingData(dtlsClient.wMemBio, pendingSendBuffer, pendingSendLength);


	//if clienthello 
}

void WriteData(uint8_t* rawData, size_t rawDataLength, uint8_t* encryptedData, size_t* encryptedDataLength, const char* endpoint)
{

	auto it = clients.find(std::string{ endpoint });
	if (it == clients.end())
	{
		std::cout << "WriteData() endpoint not found" << "\n";
		return;
	}

	DTLSClient& dtlsClient = it->second;


	int bytesWritten = SSL_write(dtlsClient.ssl, rawData, rawDataLength);


	if (bytesWritten <= 0)
	{
		std::cout << "WriteData() error in SSL_write: " << bytesWritten << "\n";
		printError(dtlsClient.ssl, bytesWritten);
		//return;
	}
	std::cout << "bytes written in ssl_write: " << bytesWritten << "\n";


	int pending = BIO_pending(dtlsClient.wMemBio);

	std::cout << "WriteData() pending bytes after ssl_write: " << pending << "\n";

	uint8_t encryptedDataBuffer[4096];
	int bytesRead = BIO_read(dtlsClient.wMemBio, encryptedDataBuffer, pending);

	if (bytesRead <= 0)
	{
		std::cout << "WriteData error reading encrypted bytes after ssl_write" << "\n";
		printError(dtlsClient.ssl, bytesRead);
	}

	std::cout << "bytes read from write bio: " << bytesRead << "\n";

	xorFilter::xorData(reinterpret_cast<char*>(encryptedDataBuffer), bytesRead, 0x1BC257E12C598C63);
	std::memcpy(encryptedData, encryptedDataBuffer, pending);
	*encryptedDataLength = pending;
}
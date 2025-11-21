#include "pch.h"

#include <iostream>
#include "DTLS.h"

#include <unordered_map>
#include <vector>
#include <openssl/ssl.h>

#include "xorBio.h"
#include <openssl/err.h>


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
};

std::unordered_map<std::string, DTLSClient> clients;

DTLSClient* createDTLSClient(const char* endpoint)
{
	auto [it, inserted] = clients.try_emplace(std::string{ endpoint });

	if (!inserted) {
		std::cout << "client exists" << it->first << "\n";

		return &it->second;
	}

	std::cout << "didn't find client in map, creating one" << "\n";

	DTLSClient& dtlsClient = it->second;

	SSL_CTX* ctx = SSL_CTX_new(DTLS_server_method());
	SSL_CTX_set_cookie_generate_cb(ctx, generateCookie);
	SSL_CTX_set_cookie_verify_cb(ctx, verifyCookie);
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, verify);
	SSL_CTX_set_cipher_list(ctx, "HIGH");
	SSL_CTX_set_psk_server_callback(ctx, psk_server_callback);

	SSL* ssl = SSL_new(ctx);
	dtlsClient.ssl = ssl;

	BIO* rMemBio = BIO_new(BIO_s_mem());
	BIO* wMemBio = BIO_new(BIO_s_mem());

	dtlsClient.rMemBio = rMemBio;
	dtlsClient.wMemBio = wMemBio;

	SSL_set_bio(ssl, rMemBio, wMemBio);

	SSL_set_accept_state(ssl);

	return &dtlsClient;
}



void ReadData(uint8_t* inputData, size_t inputDataLength, uint8_t* pendingSendBuffer, size_t* pendingSendLength, uint8_t* decrpytedDataBuffer, size_t* decryptedDataLength, const char* endpoint)
{
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();

	std::cout << endpoint;
	DTLSClient* dtlsClient = createDTLSClient(endpoint);


	std::cout << "input data length" << inputDataLength << "\n";

	for (int i = 0; i < inputDataLength; i++)
	{
		std::cout << std::hex << (int)inputData[i] << " ";
	}

	xorFilter::xorData(reinterpret_cast<char*>(inputData), inputDataLength, 0x1BC257E12C598C63);
	BIO_write(dtlsClient->rMemBio, inputData, inputDataLength);

	bool isHandshakeFinished = SSL_is_init_finished(dtlsClient->ssl);
	if (!isHandshakeFinished)
	{
		int result = SSL_do_handshake(dtlsClient->ssl);

		std::cout << "do_handshake_result" << result << "\n";

		if (result < 1)
		{
			int ssl_error = SSL_get_error(dtlsClient->ssl, result);
			std::cout << "SSL error code: " << ssl_error << "\n";

			unsigned long e = ERR_get_error();

			char buf[256];
			ERR_error_string_n(e, buf, sizeof(buf));
			printf("Error: %s\n", buf);


			const char* reason = ERR_reason_error_string(e);

			switch (result) {
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

	}

	int pendingSize = BIO_pending(dtlsClient->wMemBio);
	std::cout << "pending size" << pendingSize << "\n";

	if (pendingSize > 0)
	{
		uint8_t pendingData[4096];
		int bytesRead = BIO_read(dtlsClient->wMemBio, pendingData, pendingSize);
		xorFilter::xorData(reinterpret_cast<char*>(pendingData), pendingSize, 0x1BC257E12C598C63);

		std::memcpy(pendingSendBuffer, pendingData, bytesRead);
		*pendingSendLength = bytesRead;

		std::cout << "bytes read" << bytesRead << "\n";

		for (int i = 0; i < bytesRead; i++)
		{
			std::cout << std::hex << (int)pendingData[i] << " ";
		}
	}

	if (isHandshakeFinished)
	{
		std::cout << "handshake finished";
		uint8_t decryptedData[4096];
		int bytesRead = SSL_read(dtlsClient->ssl, decryptedData, sizeof(decryptedData));

		if (bytesRead > 0)
		{
			std::cout << "decrypted bytes read" << bytesRead << "\n";
			for (int i = 0; i < bytesRead; i++)
			{
				std::cout << std::hex << (int)decryptedData[i] << " ";
			}
			std::cout << "\n";
			std::memcpy(decrpytedDataBuffer, decryptedData, bytesRead);
			*decryptedDataLength = bytesRead;
		}
		else
		{
			int ssl_error = SSL_get_error(dtlsClient->ssl, bytesRead);
			std::cout << "SSL read error code: " << ssl_error << "\n";
		}
	}


}


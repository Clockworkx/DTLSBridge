#include "DTLS.h"

#include <cstring>
#include <ctime>
#ifdef LOGGING
#include <iostream>
#endif
#include <string>
#include <unordered_map>
#include <vector>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#include "DtlsRecord.h"
#include "Globals.h"
#include "xorBio.h"

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

const unsigned char pskS[] = { 0x4F, 0x74, 0x57, 0x72, 0x4C, 0x66, 0x77, 0x56, 0x6A, 0x6D, 0x59, 0x6D, 0x45, 0x6B };

unsigned int psk_server_callback(SSL* ssl, const char* identity, unsigned char* psk, unsigned int max_psk_len)
{
	if (identity != nullptr)
	{
#ifdef LOGGING
		std::cout << "PSK identity: " << identity << "\n";
#endif

		if (strcmp(identity, "c4ad847c") == 0
			&& sizeof(pskS) <= max_psk_len
			)
		{
			memcpy(psk, pskS, sizeof(pskS));
			return sizeof(pskS);
		}
	}
	return 0;
}

struct DTLSClient
{
	SSL* ssl;
	BIO* rMemBio;
	BIO* wMemBio;
	time_t last_traffic;
	bool hasExchangedCookie;
};


void init()
{
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();

	SSL_CTX* ctx = SSL_CTX_new(DTLS_server_method());
	SSL_CTX_set_cookie_generate_cb(ctx, generateCookie);
	SSL_CTX_set_cookie_verify_cb(ctx, verifyCookie);
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, verify);
	SSL_CTX_set_cipher_list(ctx, "HIGH");
	SSL_CTX_set_psk_server_callback(ctx, psk_server_callback);
	Globals::ctx = ctx;
}

std::unordered_map<std::string, DTLSClient> clients;

void collectGarbage(time_t ts)
{
#ifdef LOGGING
	std::cout << "Running garbage collector" << "\n";
#endif
	for (auto it = clients.begin(); it != clients.end(); )
	{
		const auto secs_since_last_traffic = ts - it->second.last_traffic;
		if (secs_since_last_traffic > 120)
		{
#ifdef LOGGING
			std::cout << "Garbage collector dropping client: " << it->first << "\n";
#endif
			SSL_free(it->second.ssl);
			it = clients.erase(it);
		}
		else
		{
			++it;
		}
	}
}

#ifdef LOGGING
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
#endif

void getPendingData(BIO* writeBio, uint8_t target[4096], size_t* pendingBytesWritten)
{
	int pendingSize = BIO_pending(writeBio);
#ifdef LOGGING
	std::cout << "getPendingData() write bio pending size: " << pendingSize << "\n";
#endif

	if (pendingSize <= 0)
	{
#ifdef LOGGING
		std::cout << "Tried reading pending write data but no pending data in bio" << "\n";
#endif
		*pendingBytesWritten = 0;
		return;
	}

	if (pendingSize > 4096)
	{
#ifdef LOGGING
		std::cout << "Trimming pending write data to buffer size: " << pendingSize << " -> " << 4096 << "\n";
#endif
		pendingSize = 4096;

	}

	int bytesRead = BIO_read(writeBio, target, pendingSize);

#ifdef LOGGING
	std::cout << "getPendingData() bytes read from write bio:" << bytesRead << "\n";
#endif

	if (bytesRead < 0)
	{
		bytesRead = 0;
	}

#ifdef LOGGING
	for (int i = 0; i < bytesRead; i++)
	{
		std::cout << std::hex << (int)target[i] << " ";
	}
	std::cout << "\n";
#endif

	xorFilter::xorData(reinterpret_cast<char*>(target), bytesRead);

	*pendingBytesWritten = bytesRead;
}

void handleNewClient(const uint8_t* inputData, size_t inputDataLength, uint8_t pendingSendBuffer[4096], size_t* pendingSendLength, const char* endpoint)
{
#ifdef LOGGING
	std::cout << "endpoint not found, checking for cookie" << "\n";
#endif
	SSL* ssl = SSL_new(Globals::ctx);

	BIO* rMemBio = BIO_new(BIO_s_mem());
	BIO* wMemBio = BIO_new(BIO_s_mem());

	SSL_set_bio(ssl, rMemBio, wMemBio);
	SSL_set_accept_state(ssl);

	int bioWritten = BIO_write(rMemBio, inputData, inputDataLength);
#ifdef LOGGING
	std::cout << "handleNewClient() bytes written to read bio: " << bioWritten << "\n";
#endif

	BIO_ADDR* peer = BIO_ADDR_new();
	int listenRet = DTLSv1_listen(ssl, peer);
	BIO_ADDR_free(peer);

	if (listenRet < 1)
	{
#ifdef LOGGING
		std::cout << "DTLSv1_listen returned < 1" << "\n";
#endif

		if (listenRet < 0)
		{
#ifdef LOGGING
			std::cout << "Fatal Error in DTLSv1_listen" << "\n";
			printError(ssl, listenRet);
#endif
			return;
		}

#ifdef LOGGING
		std::cout << "DTLSv1_listen returned HelloVerifyRequest" << "\n";
#endif
		getPendingData(wMemBio, pendingSendBuffer, pendingSendLength);
		SSL_free(ssl);
		return;
	}

#ifdef LOGGING
	std::cout << "DTLSv1_listen succeeded, cookie verified" << "\n";
#endif
	const auto ts = ::time(nullptr);
	collectGarbage(ts);
	auto it = clients.emplace(std::string{ endpoint }, DTLSClient{ ssl, rMemBio, wMemBio, ts, true});
	DTLSClient& dtlsClient = it.first->second;

	bool isHandshakeFinished = SSL_is_init_finished(dtlsClient.ssl);

	if (!isHandshakeFinished)
	{
		int result = SSL_do_handshake(dtlsClient.ssl);
#ifdef LOGGING
		std::cout << "do_handshake_result: " << result << "\n";
		if (result < 1)
		{
			printError(dtlsClient.ssl, result);
		}
#endif
	}
	else
	{
#ifdef LOGGING
		std::cout << "Handshake already finished after DTLSv1_listen should not happen" << "\n";
#endif
	}
	getPendingData(dtlsClient.wMemBio, pendingSendBuffer, pendingSendLength);

}

void handleExistingClient(DTLSClient& dtlsClient, const uint8_t* inputData, size_t inputDataLength, uint8_t decryptedDataBuffer[4096], size_t* decryptedDataLength, uint8_t pendingSendBuffer[4096], size_t* pendingSendLength, const char* endpoint) {

	int bioWritten = BIO_write(dtlsClient.rMemBio, inputData, inputDataLength);
#ifdef LOGGING
	std::cout << "ReadData() bytes written to read bio: " << bioWritten << "\n";
#endif

	bool isHandshakeFinished = SSL_is_init_finished(dtlsClient.ssl);

	if (!isHandshakeFinished)
	{
		int result = SSL_do_handshake(dtlsClient.ssl);
#ifdef LOGGING
		std::cout << "do_handshake_result: " << result << "\n";
		if (result < 1)
		{
			printError(dtlsClient.ssl, result);
		}
#endif
		getPendingData(dtlsClient.wMemBio, pendingSendBuffer, pendingSendLength);
	}

	if (isHandshakeFinished)
	{
#ifdef LOGGING
		std::cout << "ReadData() handshake finished" << "\n";
#endif

		int bytesRead = SSL_read(dtlsClient.ssl, decryptedDataBuffer, 4096);

#ifdef LOGGING
		std::cout << "ssl_read decrypted bytes read: " << bytesRead << "\n";
#endif

		if (bytesRead > 0)
		{
#ifdef LOGGING
			for (int i = 0; i < bytesRead; i++)
			{
				std::cout << std::hex << (int)decryptedDataBuffer[i] << " ";
			}
			std::cout << "\n";
#endif
			*decryptedDataLength = bytesRead;
			getPendingData(dtlsClient.wMemBio, pendingSendBuffer, pendingSendLength);
			return;
		}
#ifdef LOGGING
		std::cout << "ssl_read bytesRead <= 0" << "\n";
		printError(dtlsClient.ssl, bytesRead); 
		std::cout << "checking for close notify" << "\n";
#endif
		const int shutdownMask = SSL_get_shutdown(dtlsClient.ssl);

		const bool receivedCloseNotify = (shutdownMask & SSL_RECEIVED_SHUTDOWN) != 0;

		if (receivedCloseNotify) {
#ifdef LOGGING
			std::cout << "DTLS received close-notify. Deleting client\n";
#endif
			getPendingData(dtlsClient.wMemBio, pendingSendBuffer, pendingSendLength);
			SSL_free(dtlsClient.ssl);
			clients.erase({ endpoint });
			return;
		}

		getPendingData(dtlsClient.wMemBio, pendingSendBuffer, pendingSendLength);

		std::vector<DTLSPlaintext> records;
		if (!parseDTLSRecords(inputData, inputDataLength, records))
		{
#ifdef LOGGING
			std::cout << "Failed to parse DTLSPlaintext record" << "\n";
#endif
			*decryptedDataLength = 0;
			*pendingSendLength = 0;
			return;
		}

		for (const auto& record : records)
		{
			if (isClientHello(record))
			{
#ifdef LOGGING
				std::cout << "Received a client Hello with existing SSL Session, deleting Session, sending hello verify request\n";
#endif
				SSL_free(dtlsClient.ssl);
				clients.erase({ endpoint });
				return handleNewClient(inputData, inputDataLength, pendingSendBuffer, pendingSendLength, endpoint);
			}
		}
	}
}

bool ReadData(uint8_t* inputData, size_t inputDataLength, uint8_t* pendingSendBuffer, size_t* pendingSendLength, uint8_t decryptedDataBuffer[4096], size_t* decryptedDataLength, const char* endpoint)
{
#ifdef LOGGING
	std::cout << "ReadData() input data length: " << inputDataLength << "\n";
#endif

	if (inputDataLength <= 0)
	{
#ifdef LOGGING
		std::cout << "ReadData() input data length is zero or negative" << "\n";
#endif
		*decryptedDataLength = 0;
		*pendingSendLength = 0;
		return false;
	}

	if (!consistsOfDTLSRecords(inputData, inputDataLength))
	{
		xorFilter::xorData(reinterpret_cast<char*>(inputData), inputDataLength);
		if (!consistsOfDTLSRecords(inputData, inputDataLength))
		{
#ifdef LOGGING
			std::cout << "ReadData() Warning: packet is not a DTLS Record after xoring" << "\n";
#endif
			*decryptedDataLength = 0;
			*pendingSendLength = 0;
			return false;
		}
	}

	auto client = clients.find(std::string{ endpoint });

	if (client == clients.end())
	{
		handleNewClient(inputData, inputDataLength, pendingSendBuffer, pendingSendLength, endpoint);
		*decryptedDataLength = 0;
		return true;
	}

	DTLSClient& dtlsClient = client->second;
	handleExistingClient(dtlsClient, inputData, inputDataLength, decryptedDataBuffer, decryptedDataLength, pendingSendBuffer, pendingSendLength, endpoint);
	dtlsClient.last_traffic = ::time(nullptr);
	return true;
}


void WriteData(const uint8_t* rawData, size_t rawDataLength, uint8_t encryptedData[4096], size_t* encryptedDataLength, const char* endpoint)
{

	auto it = clients.find(std::string{ endpoint });
	if (it == clients.end())
	{
#ifdef LOGGING
		std::cout << "WriteData() endpoint not found" << "\n";
#endif
		return;
	}

	DTLSClient& dtlsClient = it->second;

	int bytesWritten = SSL_write(dtlsClient.ssl, rawData, rawDataLength);
	if (bytesWritten <= 0)
	{
#ifdef LOGGING
		std::cout << "WriteData() error in SSL_write: " << bytesWritten << "\n";
		printError(dtlsClient.ssl, bytesWritten);
#endif
		//return;
	}
#ifdef LOGGING
	std::cout << "bytes written in ssl_write: " << bytesWritten << "\n";
#endif

	getPendingData(dtlsClient.wMemBio, encryptedData, encryptedDataLength);
	dtlsClient.last_traffic = ::time(nullptr);
}
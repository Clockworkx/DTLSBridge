#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>

namespace DTLSConstants
{
	constexpr size_t DTLS_HEADER_LEN = 13;
}

struct ProtocolVersion {
	uint8_t major;
	uint8_t minor;
};

enum ContentType : uint8_t {
	change_cipher_spec = 20,
	alert = 21,
	handshake = 22,
	application_data = 23,
	heartbeat = 24 // extension
};


struct DTLSPlaintext {
	ContentType type;
	ProtocolVersion legacy_record_version;
	uint16_t epoch;
	uint64_t sequence_number : 48;
	uint16_t length;
	std::vector<uint8_t> fragment;
};

enum HandshakeType : uint8_t {
    hello_request = 0,
    client_hello = 1,
    server_hello = 2,
    hello_verify_request = 3,           
    certificate = 11,
    server_key_exchange = 12,
    certificate_request = 13,
    server_hello_done = 14,
    certificate_verify = 15,
    client_key_exchange = 16,
    finished = 20
};

struct HandshakeMessage {
	HandshakeType msg_type;
	uint32_t length : 24;
	uint16_t message_seq;
	uint32_t fragment_offset : 24;
	uint32_t fragment_length : 24;
	std::vector<uint8_t> body;
};

bool parseDTLSPlaintext(const uint8_t* data, size_t length, DTLSPlaintext& record);
bool isClientHello(const DTLSPlaintext& record);
bool consistsOfDTLSRecords(uint8_t* packet, size_t packetLength);
bool parseDTLSRecords(const uint8_t* packet, size_t packetSize, std::vector<DTLSPlaintext>& records);

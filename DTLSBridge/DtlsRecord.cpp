#include "DtlsRecord.hpp"

#include <algorithm>
#include <array>
#ifdef LOGGING
#include <iostream>
#endif
#include <vector>

//DTLSPlaintext parseDTLSRecord(const uint8_t* data, size_t length)
//{
//	if (length < 13) // Minimum DTLS record header size
//	{
//		throw std::runtime_error("Data too short to be a valid DTLS record");
//	}
//	DTLSPlaintext record;
//	size_t offset = 0;
//	record.type = static_cast<ContentType>(data[offset]);
//	offset += 1;
//	record.legacy_record_version.major = data[offset];
//	offset += 1;
//	record.legacy_record_version.minor = data[offset];
//	offset += 1;
//	record.epoch = (data[offset] << 8) | data[offset + 1];
//	offset += 2;
//	record.sequence_number = 0;
//	for (int i = 0; i < 6; ++i)
//	{
//		record.sequence_number = (record.sequence_number << 8) | data[offset + i];
//	}
//	offset += 6;
//	record.length = (data[offset] << 8) | data[offset + 1];
//	offset += 2;
//	if (offset + record.length > length)
//	{
//		throw std::runtime_error("Fragment length exceeds available data");
//	}
//	record.fragment.insert(record.fragment.end(), data + offset, data + offset + record.length);
//	return record;
//}



bool parseDTLSRecords(const uint8_t* packet, size_t packetSize, std::vector<DTLSPlaintext>& records)
{
	if (packetSize < DTLSConstants::DTLS_HEADER_LEN)
	{
#ifdef LOGGING
		std::cout << "Malformed packet: too small for a record\n";
#endif
		return false;

	}

	size_t bytesRead = 0;
	while (bytesRead < packetSize)
	{
		DTLSPlaintext record;
		if (!parseDTLSPlaintext(packet + bytesRead, packetSize - bytesRead, record))
		{
#ifdef LOGGING
			std::cout << "Malformed DTLS Record\n";
#endif
			return false;
		}
		records.push_back(record);
		bytesRead += DTLSConstants::DTLS_HEADER_LEN + record.length;
	}

	return true;
}



bool parseDTLSPlaintext(const uint8_t* data, size_t length, DTLSPlaintext& record) {
	if (length < DTLSConstants::DTLS_HEADER_LEN) return false;

	record.type = static_cast<ContentType>(data[0]);
	record.legacy_record_version.major = data[1];
	record.legacy_record_version.minor = data[2];
	record.epoch = (data[3] << 8) | data[4];
	record.sequence_number =
		(uint64_t)data[5] << 40 |
		(uint64_t)data[6] << 32 |
		(uint64_t)data[7] << 24 |
		(uint64_t)data[8] << 16 |
		(uint64_t)data[9] << 8 |
		(uint64_t)data[10];
	record.length = (data[11] << 8) | data[12];

	if (length < DTLSConstants::DTLS_HEADER_LEN + record.length) return false; // not enough data in packet

	record.fragment = std::vector<uint8_t>(data + DTLSConstants::DTLS_HEADER_LEN, data + DTLSConstants::DTLS_HEADER_LEN + record.length);
	return true;
}

bool isValidDTLSRecord(uint8_t* packet, size_t packetLength)
{
	if (packetLength < DTLSConstants::DTLS_HEADER_LEN)
	{
#ifdef LOGGING
		std::cout << "packet is smaller than record header\n";
#endif
		return false;
	}
	static constexpr std::array<uint8_t, 4> contentTypes = {
		static_cast<uint8_t>(ContentType::change_cipher_spec),
		static_cast<uint8_t>(ContentType::alert),
		static_cast<uint8_t>(ContentType::handshake),
		static_cast<uint8_t>(ContentType::application_data)
	};
	if (std::find(contentTypes.begin(), contentTypes.end(), packet[0]) == contentTypes.end()) {
		return false;
	}

	if ((packet[1] != 0xFE && packet[2] != 0xFF) || packet[1] != 0xFE && packet[2] != 0xFD) { return false; }
	//3 and 4 are epoch
	//5-10 are sequence number

	const uint16_t length = static_cast<uint16_t>(packet[11]) << 8 | static_cast<uint16_t>(packet[12]);

	if (length + DTLSConstants::DTLS_HEADER_LEN != packetLength) {
		return false;
	}
	return true;
}

bool consistsOfDTLSRecords(uint8_t* packet, size_t packetLength)
{
	if (packetLength < DTLSConstants::DTLS_HEADER_LEN)
	{
#ifdef LOGGING
		std::cout << "packet is smaller than record header\n";
#endif
		return false;
	}


	size_t bytesRead = 0;
	uint8_t* readingPosition = packet;

	while (packetLength > bytesRead)
	{
		const uint16_t length = static_cast<uint16_t>(readingPosition[11]) << 8 | static_cast<uint16_t>(readingPosition[12]);

		if (!isValidDTLSRecord(readingPosition, length + DTLSConstants::DTLS_HEADER_LEN))
		{
#ifdef LOGGING
			std::cout << "Malformed DTLS Record\n";
#endif
			return false;
		}

		bytesRead += length + DTLSConstants::DTLS_HEADER_LEN;
		readingPosition += length + DTLSConstants::DTLS_HEADER_LEN;
	}

	if (bytesRead != packetLength)
	{
#ifdef LOGGING
		std::cout << "Bytes read does not equal sum of dtls record's lengths\n";
#endif
		return false;
	}

	return true;
}

bool isClientHello(const DTLSPlaintext& record)
{
	if (record.type != handshake)
	{
		return false;
	}

	HandshakeMessage handshake;
	auto handshakeFragment = record.fragment;
	handshake.msg_type = static_cast<HandshakeType>(handshakeFragment[0]);
	handshake.length = (static_cast<uint32_t>(handshakeFragment[1]) << 16) |
		(static_cast<uint32_t>(handshakeFragment[2]) << 8) |
		static_cast<uint32_t>(handshakeFragment[3]);
	handshake.message_seq = (static_cast<uint16_t>(handshakeFragment[4]) << 8) | static_cast<uint16_t>(handshakeFragment[5]);
	handshake.fragment_offset = (static_cast<uint32_t>(handshakeFragment[6]) << 16) |
		(static_cast<uint32_t>(handshakeFragment[7]) << 8) |
		static_cast<uint32_t>(handshakeFragment[8]);
	handshake.fragment_length = (static_cast<uint32_t>(handshakeFragment[9]) << 16) |
		(static_cast<uint32_t>(handshakeFragment[10]) << 8) |
		static_cast<uint32_t>(handshakeFragment[11]);


	return handshake.msg_type == HandshakeType::client_hello;
}
#include "protocol.h"
#include <cstring>

/**
 * @brief Creates a request packet according to the protocol.
 *
 * @param client_id The client ID.
 * @param version The protocol version.
 * @param code The request code.
 * @param payload The payload data.
 * @return std::vector<uint8_t> The formatted request packet.
 */
std::vector<uint8_t> Protocol::create_request(const std::vector<uint8_t>& client_id, uint8_t version, uint16_t code, const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> request;
    request.reserve(23 + payload.size());
    // Client ID (16 bytes)
    request.insert(request.end(), client_id.begin(), client_id.end());
    request.resize(16, 0);  // Ensure 16 bytes, pad with zeros if necessary
    // Version (1 byte)
    request.push_back(version);
    // Code (2 bytes)
    request.push_back(code & 0xFF);
    request.push_back((code >> 8) & 0xFF);
    // Payload size (4 bytes)
    uint32_t payload_size = payload.size();
    request.push_back(payload_size & 0xFF);
    request.push_back((payload_size >> 8) & 0xFF);
    request.push_back((payload_size >> 16) & 0xFF);
    request.push_back((payload_size >> 24) & 0xFF);
    // Payload
    request.insert(request.end(), payload.begin(), payload.end());
    return request;
}

/**
 * @brief Parses the header of a response packet.
 *
 * @param response The complete response packet.
 * @return std::tuple<std::vector<uint8_t>, uint8_t, uint16_t, uint32_t>
 *         A tuple containing client_id, version, code, and payload_size.
 */
std::tuple<std::vector<uint8_t>, uint8_t, uint16_t, uint32_t> Protocol::parse_response_header(const std::vector<uint8_t>& response) {
    std::vector<uint8_t> client_id(response.begin(), response.begin() + 16);
    uint8_t version = response[16];
    uint16_t code = *reinterpret_cast<const uint16_t*>(&response[17]);
    uint32_t payload_size = *reinterpret_cast<const uint32_t*>(&response[19]);
    return std::make_tuple(client_id, version, code, payload_size);
}
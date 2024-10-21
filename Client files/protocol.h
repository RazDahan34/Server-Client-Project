#pragma once

#include <vector>
#include <cstdint>
#include <tuple>

class Protocol {
public:
    static std::vector<uint8_t> create_request(const std::vector<uint8_t>& client_id, uint8_t version, uint16_t code, const std::vector<uint8_t>& payload);
    static std::tuple<std::vector<uint8_t>, uint8_t, uint16_t, uint32_t> parse_response_header(const std::vector<uint8_t>& response);
};

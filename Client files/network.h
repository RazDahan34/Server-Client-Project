#pragma once

#include <string>
#include <vector>
#include <boost/asio.hpp>

using boost::asio::ip::tcp;

class NetworkClient {
public:
    NetworkClient(const std::string& ip, int port);

    void send_data(const std::vector<uint8_t>& data);
    std::vector<uint8_t> receive_data();

private:
    boost::asio::io_context m_io_context;
    tcp::socket m_socket;
};

#include "network.h"
#include <stdexcept>

/**
 * @brief Constructs a NetworkClient object and establishes a connection.
 *
 * @param ip The IP address of the server to connect to.
 * @param port The port number to connect to on the server.
 */
NetworkClient::NetworkClient(const std::string& ip, int port)
    : m_socket(m_io_context)
{
    tcp::resolver resolver(m_io_context);
    tcp::resolver::results_type endpoints =
        resolver.resolve(ip, std::to_string(port));
    boost::asio::connect(m_socket, endpoints);
}

/**
 * @brief Sends data over the network connection.
 *
 * @param data The data to be sent.
 */
void NetworkClient::send_data(const std::vector<uint8_t>& data)
{
    boost::asio::write(m_socket, boost::asio::buffer(data));
}

/**
 * @brief Receives data from the network connection.
 *
 * @return std::vector<uint8_t> The received data.
 */
std::vector<uint8_t> NetworkClient::receive_data()
{
    std::vector<uint8_t> received_data(1024);
    size_t length = m_socket.read_some(boost::asio::buffer(received_data));
    received_data.resize(length);
    return received_data;
}
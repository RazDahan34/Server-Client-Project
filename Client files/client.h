#pragma once

#include <string>
#include <vector>
#include "crypto.h"
#include "network.h"
#define MAX_PACKET_SIZE 1024

class Client {
public:
    Client(const std::string& ip, int port, const std::string& username);
    ~Client();

    void register_client();
    void reconnect();
    void setup_rsa_keys();
    void exchange_keys();
    void send_file(const std::string& file_path);

private:
    std::string m_ip;
    int m_port;
    std::string m_username;
    std::vector<uint8_t> m_client_id;
    RSAKeys m_rsa_keys;
    std::vector<uint8_t> m_aes_key;
    NetworkClient m_network;

    void handle_server_response(const std::vector<uint8_t>& response);
    void send_request(uint16_t code, const std::vector<uint8_t>& payload);
};

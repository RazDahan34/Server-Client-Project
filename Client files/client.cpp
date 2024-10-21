#include "client.h"
#include "file_handler.h"
#include "protocol.h"
#include <stdexcept>
#include <iostream>

/**
 * @brief Constructs a new Client object.
 *
 * Initializes the client with the given server IP, port, and username.
 * Also sets up the network connection.
 */
Client::Client(const std::string& ip, int port, const std::string& username)
    : m_ip(ip), m_port(port), m_username(username), m_network(ip, port) {}

Client::~Client() = default;

/**
 * @brief Registers the client with the server.
 *
 * Sends a registration request to the server, receives a client ID,
 * and saves the client information locally.
 */
void Client::register_client() {
    std::cout << "Sending registration request" << std::endl;
    std::vector<uint8_t> payload(m_username.begin(), m_username.end());
    payload.resize(255, 0);  // Pad with zeros to 255 bytes
    send_request(825, payload);

    auto response = m_network.receive_data();
    handle_server_response(response);
    std::cout << "Registration successful. Client ID received: " << std::endl;
    // Save client info to me.info
    FileHandler::save_me_info(m_username, m_client_id);
}

/**
 * @brief Reconnects an existing client to the server.
 *
 * Reads stored client information and sends a reconnection request to the server.
 */
void Client::reconnect() {
    auto [name, client_id] = FileHandler::read_me_info();
    m_client_id = client_id;

    std::vector<uint8_t> payload(m_username.begin(), m_username.end());
    payload.resize(255, 0);  // Pad with zeros to 255 bytes

    std::cout << "Sending reconnection request with username: " << m_username << std::endl;
    send_request(827, payload);

    auto response = m_network.receive_data();
    handle_server_response(response);
}

/**
 * @brief Sets up RSA keys for the client.
 *
 * Loads existing RSA keys if available, otherwise generates new ones.
 */
void Client::setup_rsa_keys() {
    if (FileHandler::priv_key_exists()) {
        try {
            m_rsa_keys = Crypto::load_rsa_keys();
        }
        catch (const std::exception& e) {
            std::cerr << "Error loading private key: " << e.what() << std::endl;
            m_rsa_keys = Crypto::generate_rsa_keys();  // Regenerate if invalid
        }
    }
    else {
        m_rsa_keys = Crypto::generate_rsa_keys();
        std::vector<uint8_t> priv_key_bytes;
        CryptoPP::VectorSink vs(priv_key_bytes);
        m_rsa_keys.private_key.Save(vs);
        FileHandler::save_priv_key(priv_key_bytes);
    }
}

/**
 * @brief Exchanges keys with the server.
 *
 * Sends the client's public key to the server and receives an encrypted AES key.
 */
void Client::exchange_keys() {
    std::vector<uint8_t> payload(m_username.begin(), m_username.end());
    payload.resize(255, 0);  // Pad with zeros to 255 bytes
    auto public_key = Crypto::export_public_key(m_rsa_keys.public_key);
    payload.insert(payload.end(), public_key.begin(), public_key.end());

    send_request(826, payload);

    auto response = m_network.receive_data();
    handle_server_response(response);

    // Decrypt AES key
    m_aes_key = Crypto::decrypt_aes_key(m_aes_key, m_rsa_keys.private_key);
}

/**
 * @brief Sends a file to the server.
 *
 * Reads, encrypts, and sends the file in chunks to the server.
 * Also calculates and sends CRC for verification.
 */
void Client::send_file(const std::string& file_path) {
    auto file_content = FileHandler::read_file(file_path);
    auto encrypted_content = Crypto::encrypt_aes(file_content, m_aes_key);

    // Calculate CRC
    uint32_t crc = Crypto::calculate_crc(file_content);

    uint32_t content_size = encrypted_content.size();
    uint32_t orig_file_size = file_content.size();
    uint16_t total_packets = (content_size + MAX_PACKET_SIZE - 1) / MAX_PACKET_SIZE;

    std::string file_name = FileHandler::get_file_name(file_path);
    std::vector<uint8_t> file_name_bytes(file_name.begin(), file_name.end());
    file_name_bytes.resize(255, 0);  // Pad with zeros to 255 bytes

    size_t offset = 0;
    for (uint16_t packet_number = 1; packet_number <= total_packets; ++packet_number) {
        size_t chunk_size = std::min<size_t>(MAX_PACKET_SIZE, content_size - offset);
        if (offset + chunk_size > encrypted_content.size()) {
            throw std::runtime_error("Chunk size exceeds file size");
        }

        // Prepare payload for file chunk
        std::vector<uint8_t> payload;
        payload.insert(payload.end(), reinterpret_cast<uint8_t*>(&content_size), reinterpret_cast<uint8_t*>(&content_size) + sizeof(content_size));
        payload.insert(payload.end(), reinterpret_cast<uint8_t*>(&orig_file_size), reinterpret_cast<uint8_t*>(&orig_file_size) + sizeof(orig_file_size));
        payload.insert(payload.end(), reinterpret_cast<uint8_t*>(&packet_number), reinterpret_cast<uint8_t*>(&packet_number) + sizeof(packet_number));
        payload.insert(payload.end(), reinterpret_cast<uint8_t*>(&total_packets), reinterpret_cast<uint8_t*>(&total_packets) + sizeof(total_packets));
        payload.insert(payload.end(), file_name_bytes.begin(), file_name_bytes.end());
        payload.insert(payload.end(), encrypted_content.begin() + offset, encrypted_content.begin() + offset + chunk_size);

        send_request(828, payload);
        std::cout << "Sent chunk " << packet_number << " of " << total_packets << std::endl;

        // Wait for server acknowledgment after each chunk
        auto response = m_network.receive_data();
        handle_server_response(response);

        offset += chunk_size;
    }

    // Send final CRC confirmation
    std::vector<uint8_t> crc_payload(file_name_bytes);
    crc_payload.insert(crc_payload.end(), reinterpret_cast<uint8_t*>(&crc), reinterpret_cast<uint8_t*>(&crc) + sizeof(crc));
    send_request(900, crc_payload);

    // Wait for final server confirmation
    auto final_response = m_network.receive_data();
    handle_server_response(final_response);
}

/**
 * @brief Handles the server's response to client requests.
 *
 * Processes different types of server responses and updates client state accordingly.
 */
void Client::handle_server_response(const std::vector<uint8_t>& response) {
    if (response.size() < 3) {
        throw std::runtime_error("Invalid response from server");
    }

    uint16_t code = *reinterpret_cast<const uint16_t*>(&response[1]);

    switch (code) {
    case 1600:  // Registration success
        if (response.size() < 23) {
            throw std::runtime_error("Invalid registration success response");
        }
        m_client_id = std::vector<uint8_t>(response.begin() + 7, response.begin() + 23);
        std::cout << "Server confirmed successful registration." << std::endl;
        break;
    case 1601:  // Registration failed
        throw std::runtime_error("Registration failed");
    case 1602:  // Public key accepted, AES key received
        if (response.size() <= 23) {
            throw std::runtime_error("Invalid public key accepted response");
        }
        m_aes_key = std::vector<uint8_t>(response.begin() + 23, response.end());
        std::cout << "Server accepted public key and sent encrypted AES key." << std::endl;
        break;
    case 1603:  // File accepted
        std::cout << "Server confirmed file acceptance." << std::endl;
        break;
    case 1604:  // Message accepted
        std::cout << "Server acknowledged message." << std::endl;
        break;
    case 1605:  // Reconnect confirmed
        if (response.size() <= 23) {
            throw std::runtime_error("Invalid reconnect confirmation response");
        }
        m_aes_key = std::vector<uint8_t>(response.begin() + 23, response.end());
        std::cout << "Server confirmed successful reconnection." << std::endl;
        break;
    case 1606:  // Reconnect denied
        throw std::runtime_error("Reconnection denied");
    case 1607:  // General error
        throw std::runtime_error("Server responded with an error");
    default:
        throw std::runtime_error("Unknown response code from server");
    }
}

/**
 * @brief Sends a request to the server.
 *
 * Creates and sends a request with the specified code and payload.
 */
void Client::send_request(uint16_t code, const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> request = Protocol::create_request(m_client_id, 3, code, payload);
    m_network.send_data(request);
}

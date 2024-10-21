#include "file_handler.h"
#include <fstream>
#include <stdexcept>
#include <filesystem>
#include <iomanip>

namespace fs = std::filesystem;

/**
 * @brief Reads transfer information from the transfer.info file.
 *
 * @return TransferInfo struct containing IP, port, username, and file path.
 */
TransferInfo FileHandler::read_transfer_info() {
    std::ifstream file("C:/maman15/maman15/transfer.info");
    if (!file) {
        throw std::runtime_error("Unable to open transfer.info");
    }
    TransferInfo info;
    std::string ip_port;
    std::getline(file, ip_port);
    size_t colon_pos = ip_port.find(':');
    if (colon_pos == std::string::npos) {
        throw std::runtime_error("Invalid IP:Port format in transfer.info");
    }
    info.ip = ip_port.substr(0, colon_pos);
    info.port = std::stoi(ip_port.substr(colon_pos + 1));
    std::getline(file, info.username);
    std::getline(file, info.file_path);
    return info;
}

/**
 * @brief Checks if the me.info file exists.
 *
 * @return bool True if the file exists, false otherwise.
 */
bool FileHandler::me_info_exists() {
    return fs::exists("me.info");
}

/**
 * @brief Saves client information to the me.info file.
 *
 * @param username The client's username.
 * @param client_id The client's ID.
 */
void FileHandler::save_me_info(const std::string& username, const std::vector<uint8_t>& client_id) {
    std::ofstream file("me.info");
    if (!file) {
        throw std::runtime_error("Unable to create me.info");
    }
    file << username << std::endl;
    for (uint8_t byte : client_id) {
        file << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    file << std::endl;
}

/**
 * @brief Reads client information from the me.info file.
 *
 * @return std::tuple<std::string, std::vector<uint8_t>> A tuple containing username and client_id.
 */
std::tuple<std::string, std::vector<uint8_t>> FileHandler::read_me_info() {
    std::ifstream file("me.info");
    if (!file) {
        throw std::runtime_error("Unable to open me.info");
    }
    std::string username;
    std::string client_id_hex;
    std::getline(file, username);
    std::getline(file, client_id_hex);
    std::vector<uint8_t> client_id;
    for (size_t i = 0; i < client_id_hex.length(); i += 2) {
        client_id.push_back(std::stoul(client_id_hex.substr(i, 2), nullptr, 16));
    }
    return std::make_tuple(username, client_id);
}

/**
 * @brief Checks if the priv.key file exists.
 *
 * @return bool True if the file exists, false otherwise.
 */
bool FileHandler::priv_key_exists() {
    return fs::exists("priv.key");
}

/**
 * @brief Saves the private key to the priv.key file.
 *
 * @param priv_key The private key to save.
 */
void FileHandler::save_priv_key(const std::vector<uint8_t>& priv_key) {
    std::ofstream file("priv.key", std::ios::binary);
    if (!file) {
        throw std::runtime_error("Unable to create priv.key");
    }
    file.write(reinterpret_cast<const char*>(priv_key.data()), priv_key.size());
}

/**
 * @brief Reads the content of a file into a byte vector.
 *
 * @param file_path The path to the file to read.
 * @return std::vector<uint8_t> The content of the file as a byte vector.
 */
std::vector<uint8_t> FileHandler::read_file(const std::string& file_path) {
    std::ifstream file(file_path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Unable to open file: " + file_path);
    }
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

/**
 * @brief Extracts the file name from a file path.
 *
 * @param file_path The full path to the file.
 * @return std::string The file name without the path.
 */
std::string FileHandler::get_file_name(const std::string& file_path) {
    return fs::path(file_path).filename().string();
}
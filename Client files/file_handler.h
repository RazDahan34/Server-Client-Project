#pragma once

#include <string>
#include <vector>
#include <tuple>

struct TransferInfo {
    std::string ip;
    int port;
    std::string username;
    std::string file_path;
};

class FileHandler {
public:
    static TransferInfo read_transfer_info();
    static bool me_info_exists();
    static void save_me_info(const std::string& username, const std::vector<uint8_t>& client_id);
    static std::tuple<std::string, std::vector<uint8_t>> read_me_info();
    static bool priv_key_exists();
    static void save_priv_key(const std::vector<uint8_t>& priv_key);
    static std::vector<uint8_t> read_file(const std::string& file_path);
    static std::string get_file_name(const std::string& file_path);
};

#include "client.h"
#include "file_handler.h"
#include <iostream>
#include <stdexcept>

int main() {
    // Set console code page to UTF-8 so console knows how to interpret string data
    SetConsoleOutputCP(CP_UTF8);

    // Enable buffering to prevent VS from chopping up UTF-8 byte sequences
    setvbuf(stdout, nullptr, _IOFBF, 1000);

    try {
        std::cout << "Starting file transfer process..." << std::endl;
        // Read transfer.info
        auto transfer_info = FileHandler::read_transfer_info();
        std::cout << "Transfer info read successfully." << std::endl;

        // Initialize client
        Client client(transfer_info.ip, transfer_info.port, transfer_info.username);
        std::cout << "Client initialized with IP: " << transfer_info.ip
            << ", Port: " << transfer_info.port
            << ", Username: " << transfer_info.username << std::endl;
        // Check if me.info exists
        if (!FileHandler::me_info_exists()) {
            std::cout << "No existing client info found. Registering as a new client" << std::endl;
            // Register new client
            client.register_client();
        }
        else {
            std::cout << "Existing client info found. Attempting to reconnect..." << std::endl;
            // Reconnect existing client
            client.reconnect();
        }

        // Generate or load RSA keys
        std::cout << "Setting up RSA keys" << std::endl;
        client.setup_rsa_keys();

        // Exchange keys with server
        std::cout << "Exchanging keys with server" << std::endl;
        client.exchange_keys();

        // Send file to server
        std::cout << "Initiating file transfer" << std::endl;
        client.send_file(transfer_info.file_path);

        std::cout << "File transfer completed successfully." << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
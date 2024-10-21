#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <cryptopp/rsa.h>

struct RSAKeys {
    CryptoPP::RSA::PrivateKey private_key;
    CryptoPP::RSA::PublicKey public_key;
};

class Crypto {
public:
    static RSAKeys generate_rsa_keys();
    static RSAKeys load_rsa_keys();
    static std::vector<uint8_t> export_public_key(const CryptoPP::RSA::PublicKey& key);
    static std::vector<uint8_t> decrypt_aes_key(const std::vector<uint8_t>& encrypted_key, const CryptoPP::RSA::PrivateKey& private_key);
    static std::vector<uint8_t> encrypt_aes(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key);
    static uint32_t calculate_crc(const std::vector<uint8_t>& data);
};

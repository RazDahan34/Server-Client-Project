#include "crypto.h"
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/crc.h>
#include <cstring>
#include <cstdint> 

/**
 * @brief Generates a new RSA key pair.
 *
 * Creates a new RSA private key and derives the public key from it.
 *
 * @return RSAKeys struct containing both private and public keys.
 */
RSAKeys Crypto::generate_rsa_keys() {
    CryptoPP::AutoSeededRandomPool rng;
    RSAKeys keys;
    keys.private_key.Initialize(rng, 1024);
    keys.public_key = CryptoPP::RSA::PublicKey(keys.private_key);
    return keys;
}

/**
 * @brief Loads RSA keys from a file.
 *
 * Reads the private key from 'priv.key' file and derives the public key.
 *
 * @return RSAKeys struct containing both private and public keys.
 */
RSAKeys Crypto::load_rsa_keys() {
    RSAKeys keys;
    CryptoPP::FileSource fs("priv.key", true);
    keys.private_key.Load(fs);
    keys.public_key = CryptoPP::RSA::PublicKey(keys.private_key);
    return keys;
}

/**
 * @brief Exports the public key to a byte vector.
 *
 * @param key The RSA public key to export.
 * @return std::vector<uint8_t> The exported public key as a byte vector.
 */
std::vector<uint8_t> Crypto::export_public_key(const CryptoPP::RSA::PublicKey& key) {
    std::vector<uint8_t> exported_key;
    CryptoPP::VectorSink vs(exported_key);
    key.Save(vs);
    return exported_key;
}

/**
 * @brief Decrypts an AES key using RSA private key.
 *
 * @param encrypted_key The encrypted AES key.
 * @param private_key The RSA private key for decryption.
 * @return std::vector<uint8_t> The decrypted AES key.
 */
std::vector<uint8_t> Crypto::decrypt_aes_key(const std::vector<uint8_t>& encrypted_key, const CryptoPP::RSA::PrivateKey& private_key) {
    std::vector<uint8_t> decrypted_key;
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(private_key);
    CryptoPP::StringSource ss(encrypted_key.data(), encrypted_key.size(), true,
        new CryptoPP::PK_DecryptorFilter(rng, decryptor,
            new CryptoPP::VectorSink(decrypted_key)
        )
    );
    return decrypted_key;
}

/**
 * @brief Encrypts data using AES in CBC mode.
 *
 * @param data The data to encrypt.
 * @param key The AES key for encryption.
 * @return std::vector<uint8_t> The encrypted data.
 */
std::vector<uint8_t> Crypto::encrypt_aes(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key) {
    std::vector<uint8_t> encrypted_data;
    // Create a zeroed IV
    std::vector<uint8_t> iv(CryptoPP::AES::BLOCKSIZE, 0);
    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryptor;
    encryptor.SetKeyWithIV(key.data(), key.size(), iv.data());
    CryptoPP::StringSource ss(data.data(), data.size(), true,
        new CryptoPP::StreamTransformationFilter(encryptor,
            new CryptoPP::VectorSink(encrypted_data)
        )
    );
    return encrypted_data;
}

/**
 * @brief Calculates the CRC32 checksum of the given data.
 *
 * @param data The data to calculate the CRC for.
 * @return uint32_t The calculated CRC32 checksum.
 */
uint32_t Crypto::calculate_crc(const std::vector<uint8_t>& data) {
    CryptoPP::CRC32 crc;
    crc.Update(data.data(), data.size());
    uint32_t result = 0;
    crc.Final(reinterpret_cast<uint8_t*>(&result));
    return result;
}
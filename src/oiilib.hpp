#ifndef OIILIB_HPP
#define OIILIB_HPP

#include <string>
#include <vector>
#include <stdexcept>
#include <cstring>
#include <openssl/evp.h>

namespace oii {

inline void sha256(const unsigned char* data, size_t len,
                   unsigned char* out) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, out, nullptr);
    EVP_MD_CTX_free(ctx);
}

inline void derive_key_iv(const std::string& password,
                          unsigned char* key, unsigned char* iv) {
    sha256(reinterpret_cast<const unsigned char*>(password.data()),
           password.size(), key);

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, key, 32);
    EVP_DigestUpdate(ctx, password.data(), password.size());
    unsigned char hash[32];
    unsigned int hash_len;
    EVP_DigestFinal_ex(ctx, hash, &hash_len);
    EVP_MD_CTX_free(ctx);
    std::memcpy(iv, hash, 16);
}

inline std::string bytes_to_morse(const std::vector<unsigned char>& data) {
    if (data.empty()) {
        return {};
    }
    std::string result;
    result.reserve(data.size() * 8 + data.size() - 1);
    for (size_t idx = 0; idx < data.size(); ++idx) {
        if (idx > 0) result.push_back('_');
        unsigned char byte = data[idx];
        for (int i = 7; i >= 0; --i) {
            result.push_back((byte >> i) & 1 ? '-' : '.');
        }
    }
    return result;
}

inline std::vector<unsigned char> morse_to_bytes(const std::string& morse_str) {
    if (morse_str.empty()) {
        return {};
    }
    std::vector<unsigned char> result;
    size_t pos = 0;
    while (pos < morse_str.length()) {
        size_t end = morse_str.find('_', pos);
        if (end == std::string::npos) {
            end = morse_str.length();
        }
        size_t len = end - pos;
        if (len != 8) {
            throw std::runtime_error(
                "morse group length (" + std::to_string(len)
                + ") is not 8 at position " + std::to_string(pos));
        }
        unsigned char byte = 0;
        for (size_t j = 0; j < 8; ++j) {
            char c = morse_str[pos + j];
            if (c == '.') {
                byte = (byte << 1);
            } else if (c == '-') {
                byte = (byte << 1) | 1;
            } else {
                throw std::runtime_error(
                    std::string("invalid character '") + c
                    + "' at position " + std::to_string(pos + j)
                    + "; expected '.' or '-'");
            }
        }
        result.push_back(byte);
        pos = end + 1;
    }
    return result;
}

inline std::vector<unsigned char> aes_encrypt(
        const std::string& plaintext,
        const std::string& password) {

    unsigned char key[32], iv[16];
    derive_key_iv(password, key, iv);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("failed to create EVP_CIPHER_CTX");
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(),
                                nullptr, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    }

    std::vector<unsigned char> ciphertext(plaintext.size() + 32);
    int out_len = 0, tmp_len = 0;

    if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &out_len,
            reinterpret_cast<const unsigned char*>(plaintext.data()),
            static_cast<int>(plaintext.size()))) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptUpdate failed");
    }

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + out_len, &tmp_len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    }
    out_len += tmp_len;
    ciphertext.resize(static_cast<size_t>(out_len));

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

inline std::string aes_decrypt(
        const std::vector<unsigned char>& ciphertext,
        const std::string& password) {

    unsigned char key[32], iv[16];
    derive_key_iv(password, key, iv);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("failed to create EVP_CIPHER_CTX");
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(),
                                nullptr, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptInit_ex failed");
    }

    std::vector<unsigned char> plaintext(ciphertext.size());
    int out_len = 0, tmp_len = 0;

    if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &out_len,
            ciphertext.data(),
            static_cast<int>(ciphertext.size()))) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptUpdate failed");
    }

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len, &tmp_len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error(
            "EVP_DecryptFinal_ex failed — wrong password or corrupted data");
    }
    out_len += tmp_len;
    plaintext.resize(static_cast<size_t>(out_len));

    EVP_CIPHER_CTX_free(ctx);
    return std::string(plaintext.begin(), plaintext.end());
}

} // namespace oii

#endif

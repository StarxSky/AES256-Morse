#include "oiilib.hpp"
#include <iostream>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: oiienc <password> [plaintext]\n"
                  << "Encrypt plaintext using AES-256-CBC and encode as morse string.\n"
                  << "If plaintext is omitted, read from stdin.\n";
        return 1;
    }

    std::string password = argv[1];
    std::string plaintext;

    if (argc >= 3) {
        plaintext = argv[2];
    } else {
        std::string line;
        bool first = true;
        while (std::getline(std::cin, line)) {
            if (!first) plaintext += '\n';
            plaintext += line;
            first = false;
        }
    }

    try {
        auto ciphertext = oii::aes_encrypt(plaintext, password);
        std::cout << oii::bytes_to_morse(ciphertext) << '\n';
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << '\n';
        return 1;
    }

    return 0;
}

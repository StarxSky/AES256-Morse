#include "oiilib.hpp"
#include <iostream>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: oiidec <password> [ciphertext]\n"
                  << "Decode morse string and decrypt using AES-256-CBC.\n"
                  << "If ciphertext is omitted, read from stdin.\n";
        return 1;
    }

    std::string password = argv[1];
    std::string morse_str;

    if (argc >= 3) {
        morse_str = argv[2];
    } else {
        std::getline(std::cin, morse_str);
    }

    try {
        auto ciphertext = oii::morse_to_bytes(morse_str);
        std::string plaintext = oii::aes_decrypt(ciphertext, password);
        std::cout << plaintext;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << '\n';
        return 1;
    }

    return 0;
}

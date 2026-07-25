#include <sodium.h>
#include <iostream>
#include <vector>
#include <cstring>

int main() {
    if (sodium_init() < 0) return 1;

    const char* private_key_hex = "43a14b4c09100a125cd03210508857f4359efb15af4ff4012dcf0a2a21414657";
    const char* public_key_hex  = "a364fd4ec69dac2bef4cb8c70f0aaf0275d1bc63a6a052aa88052ded3dd7a333";
    const char* sealed_hex      = "e26f52168c0975a09d608c4cd9b748e660149430746a0b2defa256e7fd0c7c2ce4bcf9d1823ecac82835473864127aa7482d709b9ac1674e67ffaa3cc7ebb65ed2a3114c2bb069eb390479f77dd8e09738";

    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    unsigned char sk[crypto_box_SECRETKEYBYTES];
    size_t bin_len;

    sodium_hex2bin(pk, sizeof(pk), public_key_hex, strlen(public_key_hex), nullptr, &bin_len, nullptr);
    sodium_hex2bin(sk, sizeof(sk), private_key_hex, strlen(private_key_hex), nullptr, &bin_len, nullptr);

    size_t sealed_len = strlen(sealed_hex) / 2;
    std::vector<unsigned char> sealed(sealed_len);
    sodium_hex2bin(sealed.data(), sealed.size(), sealed_hex, strlen(sealed_hex), nullptr, &bin_len, nullptr);
    sealed.resize(bin_len);

    if (sealed.size() < crypto_box_SEALBYTES) {
        std::cerr << "Sealed data too small\n";
        return 1;
    }

    std::vector<unsigned char> plaintext(sealed.size() - crypto_box_SEALBYTES);

    int ret = crypto_box_seal_open(plaintext.data(), sealed.data(), sealed.size(), pk, sk);

    if (ret != 0) {
        std::cerr << "Decryption failed\n";
        return 1;
    }

    std::string message(reinterpret_cast<char*>(plaintext.data()), plaintext.size());
    std::cout << "Decrypted in C++: " << message << "\n";

    return 0;
}
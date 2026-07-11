#include <sodium.h>
#include <iostream>
#include <vector>
#include <cstring>

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0]
                  << " <relay1_pubkey_hex> <relay2_pubkey_hex> <relay2_hashid_hex>\n";
        std::cerr << "Builds a 2-layer packet: outer layer sealed for relay1,\n";
        std::cerr << "pointing to relay2's hashid, wrapping an inner final\n";
        std::cerr << "layer sealed for relay2.\n";
        return 1;
    }

    if (sodium_init() < 0) return 1;

    unsigned char relay1_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char relay2_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char relay2_hashid[crypto_generichash_BYTES];
    size_t bin_len;

    if (sodium_hex2bin(relay1_pk, sizeof(relay1_pk), argv[1], strlen(argv[1]), nullptr, &bin_len, nullptr) != 0) {
        std::cerr << "Invalid relay1 pubkey hex\n";
        return 1;
    }
    if (sodium_hex2bin(relay2_pk, sizeof(relay2_pk), argv[2], strlen(argv[2]), nullptr, &bin_len, nullptr) != 0) {
        std::cerr << "Invalid relay2 pubkey hex\n";
        return 1;
    }
    if (sodium_hex2bin(relay2_hashid, sizeof(relay2_hashid), argv[3], strlen(argv[3]), nullptr, &bin_len, nullptr) != 0) {
        std::cerr << "Invalid relay2 hashid hex\n";
        return 1;
    }

    // ---- Inner layer (final, for relay2) ----
    std::vector<unsigned char> plaintext_inner;
    plaintext_inner.push_back(0x01);   // final layer marker

    // fake 32-byte "sender hashid" -- doesn't need to be real for this test
    for (int i = 0; i < 32; i++) plaintext_inner.push_back((unsigned char)i);

    for(int i = 0;i<32;i++) plaintext_inner.push_back((unsigned char)(0xAA));

    std::string fake_message = "hello from a 2-hop test";
    plaintext_inner.insert(plaintext_inner.end(), fake_message.begin(), fake_message.end());

    std::vector<unsigned char> sealed_inner(plaintext_inner.size() + crypto_box_SEALBYTES);
    crypto_box_seal(sealed_inner.data(), plaintext_inner.data(), plaintext_inner.size(), relay2_pk);

    // ---- Outer layer (for relay1, points to relay2) ----
    std::vector<unsigned char> plaintext_outer;
    plaintext_outer.push_back(0x00);   // relay layer marker

    plaintext_outer.insert(plaintext_outer.end(), relay2_hashid, relay2_hashid + crypto_generichash_BYTES);
    plaintext_outer.insert(plaintext_outer.end(), sealed_inner.begin(), sealed_inner.end());

    std::vector<unsigned char> sealed_outer(plaintext_outer.size() + crypto_box_SEALBYTES);
    crypto_box_seal(sealed_outer.data(), plaintext_outer.data(), plaintext_outer.size(), relay1_pk);

    // ---- base64-encode outer layer for curl ----
    size_t b64_len = sodium_base64_ENCODED_LEN(sealed_outer.size(), sodium_base64_VARIANT_ORIGINAL);
    std::vector<char> b64(b64_len);

    sodium_bin2base64(
        b64.data(), b64.size(),
        sealed_outer.data(), sealed_outer.size(),
        sodium_base64_VARIANT_ORIGINAL
    );

    std::cout << b64.data() << "\n";

    return 0;
}
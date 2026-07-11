#include <sodium.h>
#include <iostream>
#include <vector>
#include <cstring>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <recipient_pubkey_hex>\n";
        return 1;
    }

    if (sodium_init() < 0) return 1;

    unsigned char recipient_pk[crypto_box_PUBLICKEYBYTES];
    size_t bin_len;

    if (sodium_hex2bin(
            recipient_pk, sizeof(recipient_pk),
            argv[1], strlen(argv[1]),
            nullptr, &bin_len, nullptr) != 0) {
        std::cerr << "Invalid pubkey hex\n";
        return 1;
    }

    // Build a minimal fake layer: layer_type(1) + fake_next_hashid(32) + fake_payload
    std::vector<unsigned char> plaintext;
    plaintext.push_back(0x00);   // layer_type: relay layer, just for the test

    // fake 32-byte "next hashid" -- doesn't need to be real for this test,
    // we're only testing that relay_http can decode and print it
    for (int i = 0; i < 32; i++) plaintext.push_back((unsigned char)i);

    std::string fake_payload = "hello relay, this is a test payload";
    plaintext.insert(plaintext.end(), fake_payload.begin(), fake_payload.end());

    std::vector<unsigned char> sealed(plaintext.size() + crypto_box_SEALBYTES);
    crypto_box_seal(sealed.data(), plaintext.data(), plaintext.size(), recipient_pk);

    // base64-encode for curl
    size_t b64_len = sodium_base64_ENCODED_LEN(sealed.size(), sodium_base64_VARIANT_ORIGINAL);
    std::vector<char> b64(b64_len);

    sodium_bin2base64(
        b64.data(), b64.size(),
        sealed.data(), sealed.size(),
        sodium_base64_VARIANT_ORIGINAL
    );

    std::cout << b64.data() << "\n";

    return 0;
}
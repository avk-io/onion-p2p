#include <bits/stdc++.h>
#include <asio.hpp>
#include <sodium.h>
#include <fstream>
#include <arpa/inet.h>

using asio::ip::tcp;

int main() {
    try {
        if (sodium_init() < 0)
            return 1;

        unsigned char a_pk[crypto_box_PUBLICKEYBYTES];
        unsigned char a_sk[crypto_box_SECRETKEYBYTES];

        // Load or generate keypair
        std::ifstream keyfile_in("onion_a.key", std::ios::binary);

        if (keyfile_in) {
            keyfile_in.read(reinterpret_cast<char*>(a_pk), sizeof(a_pk));
            keyfile_in.read(reinterpret_cast<char*>(a_sk), sizeof(a_sk));

            if (!keyfile_in) {
                std::cerr << "Failed to read key file\n";
                return 1;
            }
        } else {
            crypto_box_keypair(a_pk, a_sk);

            std::ofstream keyfile_out("onion_a.key", std::ios::binary);
            keyfile_out.write(reinterpret_cast<char*>(a_pk), sizeof(a_pk));
            keyfile_out.write(reinterpret_cast<char*>(a_sk), sizeof(a_sk));

            if (!keyfile_out) {
                std::cerr << "Failed to write key file\n";
                return 1;
            }
        }

        unsigned char hash_a[crypto_generichash_BYTES];
        crypto_generichash(
            hash_a,
            sizeof(hash_a),
            a_pk,
            sizeof(a_pk),
            nullptr,
            0
        );

        const char* P1_PUBKEY_HEX =
            "08143afae99931a861573c9d769970cc6d2bb7ca0d6adcf113e45b6aa10f5e6a";

        const char* B_PUBKEY_HEX =
            "a74dec1bbf1a5e831bd0ff7f4b3bc1a8a5f6afd333dfe777f9044da253a52c4c";

        unsigned char p1_pk[crypto_box_PUBLICKEYBYTES];
        unsigned char b_pk[crypto_box_PUBLICKEYBYTES];

        size_t bin_len;

        int r1 = sodium_hex2bin(
            p1_pk,
            sizeof(p1_pk),
            P1_PUBKEY_HEX,
            strlen(P1_PUBKEY_HEX),
            nullptr,
            &bin_len,
            nullptr
        );

        int r2 = sodium_hex2bin(
            b_pk,
            sizeof(b_pk),
            B_PUBKEY_HEX,
            strlen(B_PUBKEY_HEX),
            nullptr,
            &bin_len,
            nullptr
        );

        if (r1 != 0 || r2 != 0) {
            std::cerr << "Failed to decode public keys\n";
            return 1;
        }

        unsigned char hash_b[crypto_generichash_BYTES];

        crypto_generichash(
            hash_b,
            sizeof(hash_b),
            b_pk,
            sizeof(b_pk),
            nullptr,
            0
        );

        std::string message =
            "hello B, via P1, single-hop onion test";

        // ------------------------
        // Build plaintext for B
        // ------------------------

        std::vector<unsigned char> plaintext_b;

        plaintext_b.insert(
            plaintext_b.end(),
            hash_a,
            hash_a + crypto_generichash_BYTES
        );

        plaintext_b.insert(
            plaintext_b.end(),
            message.begin(),
            message.end()
        );

        std::vector<unsigned char> sealed_b(
            plaintext_b.size() + crypto_box_SEALBYTES
        );

        crypto_box_seal(
            sealed_b.data(),
            plaintext_b.data(),
            plaintext_b.size(),
            b_pk
        );

        // ------------------------
        // Build plaintext for P1
        // ------------------------

        std::vector<unsigned char> plaintext_p1;

        plaintext_p1.insert(
            plaintext_p1.end(),
            hash_b,
            hash_b + crypto_generichash_BYTES
        );

        plaintext_p1.insert(
            plaintext_p1.end(),
            sealed_b.begin(),
            sealed_b.end()
        );

        std::vector<unsigned char> sealed_p1(
            plaintext_p1.size() + crypto_box_SEALBYTES
        );

        crypto_box_seal(
            sealed_p1.data(),
            plaintext_p1.data(),
            plaintext_p1.size(),
            p1_pk
        );

        // ------------------------
        // Send to P1
        // ------------------------

        asio::io_context io;

        tcp::resolver resolver(io);

        auto endpoints =
            resolver.resolve("127.0.0.1", "7100");

        tcp::socket socket(io);

        asio::connect(socket, endpoints);

        uint32_t len_net =
            htonl(static_cast<uint32_t>(sealed_p1.size()));

        asio::write(
            socket,
            asio::buffer(&len_net, sizeof(len_net))
        );

        asio::write(
            socket,
            asio::buffer(sealed_p1)
        );

        std::cout << "Sent onion packet to P1\n";
    }
    catch (const std::exception& e) {
        std::cerr << "Exception: "
                  << e.what() << '\n';
        return 1;
    }

    return 0;
}
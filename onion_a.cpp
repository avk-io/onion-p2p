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

        const char* P1_PUBKEY_HEX = "c562e85705bf7a53b1f380afd88302d2e45604cef971e50baa8bffcfd1a6d70f";
        const char* P2_PUBKEY_HEX = "a40765e3e8bd847ab65addeb47ee3df2e07ef3cc97ab1b4d0982f57533713c3f";
        const char* P3_PUBKEY_HEX = "0ea31789631e5d810833d58813fd8ce530a3d334898e79f98facdbdbb64ccc6f";
        const char* B_PUBKEY_HEX  = "a74dec1bbf1a5e831bd0ff7f4b3bc1a8a5f6afd333dfe777f9044da253a52c4c";

        unsigned char p1_pk[crypto_box_PUBLICKEYBYTES];
        unsigned char p2_pk[crypto_box_PUBLICKEYBYTES];
        unsigned char p3_pk[crypto_box_PUBLICKEYBYTES];
        unsigned char b_pk[crypto_box_PUBLICKEYBYTES];

        size_t bin_len;

        if (
            sodium_hex2bin(p1_pk,sizeof(p1_pk),P1_PUBKEY_HEX,strlen(P1_PUBKEY_HEX),nullptr,&bin_len,nullptr)!=0 ||
            sodium_hex2bin(p2_pk,sizeof(p2_pk),P2_PUBKEY_HEX,strlen(P2_PUBKEY_HEX),nullptr,&bin_len,nullptr)!=0 ||
            sodium_hex2bin(p3_pk,sizeof(p3_pk),P3_PUBKEY_HEX,strlen(P3_PUBKEY_HEX),nullptr,&bin_len,nullptr)!=0 ||
            sodium_hex2bin(b_pk,sizeof(b_pk),B_PUBKEY_HEX,strlen(B_PUBKEY_HEX),nullptr,&bin_len,nullptr)!=0
        ){
            std::cerr<<"Failed to decode public keys\n";
            return 1;
        }

       
        unsigned char hash_b[crypto_generichash_BYTES];
        unsigned char hash_p2[crypto_generichash_BYTES];
        unsigned char hash_p3[crypto_generichash_BYTES];

        crypto_generichash(
            hash_b,
            sizeof(hash_b),
            b_pk,
            sizeof(b_pk),
            nullptr,
            0
        );

        crypto_generichash(
            hash_p2,
            sizeof(hash_p2),
            p2_pk,
            sizeof(p2_pk),
            nullptr,
            0
        );

        crypto_generichash(
            hash_p3,
            sizeof(hash_p3),
            p3_pk,
            sizeof(p3_pk),
            nullptr,
            0
        );


        std::string message =
            "hello B, via P1 -> P2 -> P3";

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

        std::vector<unsigned char> plaintext_p3;

        plaintext_p3.insert(
            plaintext_p3.end(),
            hash_b,
            hash_b + crypto_generichash_BYTES
        );

        plaintext_p3.insert(
            plaintext_p3.end(),
            sealed_b.begin(),
            sealed_b.end()
        );

        std::vector<unsigned char> sealed_p3(
            plaintext_p3.size() + crypto_box_SEALBYTES
        );

        crypto_box_seal(
            sealed_p3.data(),
            plaintext_p3.data(),
            plaintext_p3.size(),
            p3_pk
        );

        std::vector<unsigned char> plaintext_p2;

        plaintext_p2.insert(
            plaintext_p2.end(),
            hash_p3,
            hash_p3 + crypto_generichash_BYTES
        );

        plaintext_p2.insert(
            plaintext_p2.end(),
            sealed_p3.begin(),
            sealed_p3.end()
        );

        std::vector<unsigned char> sealed_p2(
            plaintext_p2.size() + crypto_box_SEALBYTES
        );

        crypto_box_seal(
            sealed_p2.data(),
            plaintext_p2.data(),
            plaintext_p2.size(),
            p2_pk
        );

        std::vector<unsigned char> plaintext_p1;

        plaintext_p1.insert(
            plaintext_p1.end(),
            hash_p2,
            hash_p2 + crypto_generichash_BYTES
        );

        plaintext_p1.insert(
            plaintext_p1.end(),
            sealed_p2.begin(),
            sealed_p2.end()
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
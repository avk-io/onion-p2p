#include <bits/stdc++.h>
#include <asio.hpp>
#include <fstream>
#include <arpa/inet.h>
#include <sodium.h>

using asio::ip::tcp;

int main() {
    try {
        if(sodium_init()<0){
            std::cerr << "libsodium init failed\n";
            return 1;
        }

        unsigned char a_pk[crypto_box_PUBLICKEYBYTES];
        unsigned char a_sk[crypto_box_SECRETKEYBYTES];

        std::ifstream keyfile_in("a.key", std::ios::binary);
        if (keyfile_in) {
            keyfile_in.read(reinterpret_cast<char*>(a_pk), sizeof(a_pk));
            keyfile_in.read(reinterpret_cast<char*>(a_sk), sizeof(a_sk));
        } else {
            crypto_box_keypair(a_pk, a_sk);
            std::ofstream keyfile_out("a.key", std::ios::binary);
            keyfile_out.write(reinterpret_cast<char*>(a_pk), sizeof(a_pk));
            keyfile_out.write(reinterpret_cast<char*>(a_sk), sizeof(a_sk));
        }

        char a_pk_hex[crypto_box_PUBLICKEYBYTES * 2 + 1];
        sodium_bin2hex(a_pk_hex, sizeof(a_pk_hex), a_pk, sizeof(a_pk));
        std::cout << "A Public Key:\n" << a_pk_hex << "\n";
        const char* B_PUBKEY_HEX = "026eaa62371f5c0a90609b0feb533c99ea961d77df7dd7800d3ccad22fa6df61";
        unsigned char b_pk[crypto_box_PUBLICKEYBYTES];
        size_t bin_len;

        int ret = sodium_hex2bin(
            b_pk,
            sizeof(b_pk),
            B_PUBKEY_HEX,
            strlen(B_PUBKEY_HEX),
            nullptr,
            &bin_len,
            nullptr
        );
        if(ret!=0){
            std::cerr<<"Invalid B public key\n";
            return 1;
        }


        asio::io_context io;

        tcp::resolver resolver(io);

        tcp::resolver::results_type endpoints =
            resolver.resolve("127.0.0.1", "7000");

        tcp::socket socket(io);
        asio::connect(socket, endpoints);

        for (;;) {
            std::string s;
            std::getline(std::cin, s);

            if (s == "quit")
                break;

            unsigned char nonce[crypto_box_NONCEBYTES];
            randombytes_buf(nonce,sizeof(nonce));

            std::vector<unsigned char> ciphertext(
                s.size()+crypto_box_MACBYTES
            );

            int ret = crypto_box_easy(
                ciphertext.data(),
                reinterpret_cast<const unsigned char*>(s.data()),
                s.size(),
                nonce,
                b_pk,
                a_sk
            );

            if(ret!=0){
                std::cerr<<"Encryption failed\n";
                continue;
            }

            asio::write(socket,asio::buffer(nonce,sizeof(nonce)));

            uint32_t len_net = htonl(ciphertext.size());
            asio::write(socket,asio::buffer(&len_net,sizeof(len_net)));

            asio::write(socket,asio::buffer(ciphertext));
        }
    }
    catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << '\n';
    }

    return 0;
}
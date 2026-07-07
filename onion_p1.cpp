#include <bits/stdc++.h>
#include <asio.hpp>
#include <sodium.h>
#include <fstream>
#include <arpa/inet.h>

using asio::ip::tcp;

int main() {
    if (sodium_init() < 0)
        return 1;

    unsigned char p1_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char p1_sk[crypto_box_SECRETKEYBYTES];

    // Load or generate keypair
    std::ifstream keyfile_in("onion_p1.key", std::ios::binary);

    if (keyfile_in) {
        keyfile_in.read(reinterpret_cast<char*>(p1_pk), sizeof(p1_pk));
        keyfile_in.read(reinterpret_cast<char*>(p1_sk), sizeof(p1_sk));

        if (!keyfile_in) {
            std::cerr << "Failed to read key file\n";
            return 1;
        }
    } else {
        crypto_box_keypair(p1_pk, p1_sk);

        std::ofstream keyfile_out("onion_p1.key", std::ios::binary);
        keyfile_out.write(reinterpret_cast<char*>(p1_pk), sizeof(p1_pk));
        keyfile_out.write(reinterpret_cast<char*>(p1_sk), sizeof(p1_sk));

        if (!keyfile_out) {
            std::cerr << "Failed to write key file\n";
            return 1;
        }
    }

    char p1_pk_hex[crypto_box_PUBLICKEYBYTES * 2 + 1];
    sodium_bin2hex(
        p1_pk_hex,
        sizeof(p1_pk_hex),
        p1_pk,
        sizeof(p1_pk)
    );

    std::cout << "P1 Public Key:\n"
              << p1_pk_hex << "\n";

    asio::io_context io;
    tcp::acceptor acceptor(
        io,
        tcp::endpoint(tcp::v4(), 7100)
    );

    for (;;) {
        tcp::socket socket(io);
        acceptor.accept(socket);

        std::cout << "A connected\n";

        std::error_code error;

        // Read length
        uint32_t len_net;
        asio::read(
            socket,
            asio::buffer(&len_net, sizeof(len_net)),
            error
        );

        if (error == asio::error::eof)
            break;
        else if (error)
            throw std::system_error(error);

        uint32_t len = ntohl(len_net);

        if (len < crypto_box_SEALBYTES) {
            std::cerr << "Invalid packet\n";
            continue;
        }

        // Read sealed blob
        std::vector<unsigned char> sealed_blob(len);

        asio::read(
            socket,
            asio::buffer(sealed_blob),
            error
        );

        if (error == asio::error::eof)
            break;
        else if (error)
            throw std::system_error(error);

        // Allocate plaintext
        std::vector<unsigned char> layer_plaintext(
            len - crypto_box_SEALBYTES
        );

        if (layer_plaintext.size() < crypto_generichash_BYTES) {
            std::cerr << "Invalid payload\n";
            continue;
        }

        // Decrypt
        int ret = crypto_box_seal_open(
            layer_plaintext.data(),
            sealed_blob.data(),
            sealed_blob.size(),
            p1_pk,
            p1_sk
        );

        if (ret != 0) {
            std::cerr << "Decryption failed\n";
            continue;
        }

        // Extract next hash
        unsigned char next_hashid[crypto_generichash_BYTES];

        std::memcpy(
            next_hashid,
            layer_plaintext.data(),
            crypto_generichash_BYTES
        );

        // Remaining encrypted blob
        std::vector<unsigned char> remaining_blob(
            layer_plaintext.begin() + crypto_generichash_BYTES,
            layer_plaintext.end()
        );

        char next_hash_hex[crypto_generichash_BYTES * 2 + 1];

        sodium_bin2hex(
            next_hash_hex,
            sizeof(next_hash_hex),
            next_hashid,
            sizeof(next_hashid)
        );

        std::cout << "Next hop hash: "
                  << next_hash_hex << "\n";

        // Connect to B
        tcp::resolver resolver(io);
        auto b_endpoints =
            resolver.resolve("127.0.0.1", "7200");

        tcp::socket b_socket(io);

        asio::connect(
            b_socket,
            b_endpoints
        );

        // Send remaining blob
        uint32_t out_len = remaining_blob.size();
        uint32_t out_len_net = htonl(out_len);

        asio::write(
            b_socket,
            asio::buffer(&out_len_net, sizeof(out_len_net))
        );

        asio::write(
            b_socket,
            asio::buffer(remaining_blob)
        );

        std::cout << "Forwarded to B\n";
    }

    return 0;
}
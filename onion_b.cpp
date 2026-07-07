#include <bits/stdc++.h>
#include <asio.hpp>
#include <sodium.h>
#include <fstream>
#include <arpa/inet.h>

using asio::ip::tcp;

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr
            << "Usage: "
            << argv[0]
            << " <relay_ip> <relay_port>\n";
        return 1;
    }

    std::string relay_ip = argv[1];
    std::string relay_port = argv[2];

    unsigned short own_port = 7200;

    if (sodium_init() < 0) return 1;

    unsigned char b_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char b_sk[crypto_box_SECRETKEYBYTES];

    std::ifstream keyfile_in("onion_b.key", std::ios::binary);

    if (keyfile_in) {
        keyfile_in.read(reinterpret_cast<char*>(b_pk), sizeof(b_pk));
        keyfile_in.read(reinterpret_cast<char*>(b_sk), sizeof(b_sk));

        if (!keyfile_in) {
            std::cerr << "Failed to read key file\n";
            return 1;
        }
    } else {
        crypto_box_keypair(b_pk, b_sk);
        std::ofstream keyfile_out("onion_b.key", std::ios::binary);
        keyfile_out.write(reinterpret_cast<char*>(b_pk), sizeof(b_pk));
        keyfile_out.write(reinterpret_cast<char*>(b_sk), sizeof(b_sk));
    }

    char b_pk_hex[crypto_box_PUBLICKEYBYTES * 2 + 1];
    sodium_bin2hex(b_pk_hex, sizeof(b_pk_hex), b_pk, sizeof(b_pk));
    std::cout << "B Public Key:\n" << b_pk_hex << "\n";

    unsigned char hash[crypto_generichash_BYTES];
    crypto_generichash(hash, sizeof(hash), b_pk, sizeof(b_pk), nullptr, 0);

    char hash_hex[crypto_generichash_BYTES * 2 + 1];
    sodium_bin2hex(hash_hex, sizeof(hash_hex), hash, sizeof(hash));

    asio::io_context io;

    // ------------------------
    // Register with relay
    // ------------------------

    tcp::resolver resolver(io);
    auto relay_endpoints = resolver.resolve(relay_ip, relay_port);

    tcp::socket relay_socket(io);
    asio::connect(relay_socket, relay_endpoints);

    std::string command =
        "REGISTER 127.0.0.1 " +
        std::to_string(own_port) +
        " " +
        std::string(b_pk_hex) +
        " " +
        std::string(hash_hex) +
        "\n";

    asio::write(relay_socket, asio::buffer(command));

    asio::streambuf reg_buf;
    std::error_code reg_error;

    asio::read_until(relay_socket, reg_buf, '\n', reg_error);
    if (reg_error) throw std::system_error(reg_error);

    std::istream reg_is(&reg_buf);
    std::string response;
    std::getline(reg_is, response);

    std::cout << "Relay server: " << response << '\n';

    // Registration connection done; goes out of scope and closes naturally.

    // ------------------------
    // Listen for incoming onion packets
    // ------------------------

    tcp::acceptor acceptor(io, tcp::endpoint(tcp::v4(), own_port));

    for (;;) {
        tcp::socket socket(io);
        acceptor.accept(socket);
        std::cout << "P1 connected\n";

        std::error_code error;

        uint32_t len_net;
        asio::read(socket, asio::buffer(&len_net, sizeof(len_net)), error);
        if (error == asio::error::eof) {
            break;
        } else if (error) {
            throw std::system_error(error);
        }

        uint32_t len = ntohl(len_net);

        if (len < crypto_box_SEALBYTES) {
            std::cerr << "Invalid ciphertext length\n";
            continue;
        }

        std::vector<unsigned char> sealed_blob(len);
        asio::read(socket, asio::buffer(sealed_blob), error);
        if (error == asio::error::eof)
            break;
        else if (error)
            throw std::system_error(error);

        std::vector<unsigned char> layer_plaintext(len - crypto_box_SEALBYTES);

        if (layer_plaintext.size() < crypto_generichash_BYTES) {
            std::cerr << "Invalid payload\n";
            continue;
        }

        int ret = crypto_box_seal_open(
            layer_plaintext.data(),
            sealed_blob.data(),
            sealed_blob.size(),
            b_pk,
            b_sk
        );

        if (ret != 0) {
            std::cerr << "Decryption failed\n";
            continue;
        }

        unsigned char sender_hash[crypto_generichash_BYTES];
        std::memcpy(sender_hash, layer_plaintext.data(), crypto_generichash_BYTES);

        std::string message(
            reinterpret_cast<char*>(layer_plaintext.data() + crypto_generichash_BYTES),
            layer_plaintext.size() - crypto_generichash_BYTES
        );

        char sender_hash_hex[crypto_generichash_BYTES * 2 + 1];
        sodium_bin2hex(sender_hash_hex, sizeof(sender_hash_hex), sender_hash, sizeof(sender_hash));

        std::cout << "Sender: " << sender_hash_hex << '\n';
        std::cout << "Message: " << message << '\n';
    }

    return 0;
}
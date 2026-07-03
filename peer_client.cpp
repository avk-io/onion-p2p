#include <iostream>
#include <sstream>
#include <string>

#include <asio.hpp>
#include <sodium.h>

#include "peer.hpp"

using asio::ip::tcp;

bool verifyHashId(
    const unsigned char pk[crypto_box_PUBLICKEYBYTES],
    const unsigned char claimed_hash[crypto_generichash_BYTES])
{
    unsigned char computed_hash[crypto_generichash_BYTES];

    crypto_generichash(
        computed_hash,
        sizeof(computed_hash),
        pk,
        crypto_box_PUBLICKEYBYTES,
        nullptr,
        0
    );

    return sodium_memcmp(
        computed_hash,
        claimed_hash,
        crypto_generichash_BYTES
    ) == 0;
}

int main() {
    try {
        if (sodium_init() < 0) {
            std::cerr << "libsodium init failed\n";
            return 1;
        }

        unsigned char pk[crypto_box_PUBLICKEYBYTES];
        unsigned char sk[crypto_box_SECRETKEYBYTES];

        crypto_box_keypair(pk, sk);

        unsigned char hash[crypto_generichash_BYTES];
        crypto_generichash(
            hash,
            sizeof(hash),
            pk,
            sizeof(pk),
            nullptr,
            0
        );

        char pk_hex[crypto_box_PUBLICKEYBYTES * 2 + 1];
        char hash_hex[crypto_generichash_BYTES * 2 + 1];

        sodium_bin2hex(pk_hex, sizeof(pk_hex), pk, sizeof(pk));
        sodium_bin2hex(hash_hex, sizeof(hash_hex), hash, sizeof(hash));

        asio::io_context io;

        tcp::resolver resolver(io);
        auto endpoints = resolver.resolve("127.0.0.1", "12345");

        tcp::socket socket(io);
        asio::connect(socket, endpoints);

        std::string command =
            "REGISTER 127.0.0.1 6000 " +
            std::string(pk_hex) + " " +
            std::string(hash_hex) + "\n";

        asio::write(socket, asio::buffer(command));

        asio::streambuf buf;
        std::error_code error;

        asio::read_until(socket, buf, '\n', error);
        if (error) throw std::system_error(error);

        std::istream is(&buf);

        std::string response;
        std::getline(is, response);
        std::cout << "Server: " << response << '\n';

        asio::write(socket, asio::buffer(std::string("LIST\n")));

        asio::read_until(socket, buf, '\n', error);
        if (error) throw std::system_error(error);

        std::string line;
        std::getline(is, line);
        int n = std::stoi(line);

        std::cout << "Peer count: " << n << "\n";

        for (int i = 0; i < n; i++) {
            asio::read_until(socket, buf, '\n', error);
            if (error) throw std::system_error(error);

            std::getline(is, line);

            Peer peer;
            std::istringstream iss(line);
            iss >> peer.ip >> peer.port >> peer.pubkey >> peer.hashid;

            unsigned char peer_pk[crypto_box_PUBLICKEYBYTES];
            unsigned char peer_hash[crypto_generichash_BYTES];
            size_t bin_len;

            int r1 = sodium_hex2bin(peer_pk, sizeof(peer_pk),
                peer.pubkey.c_str(), peer.pubkey.size(), nullptr, &bin_len, nullptr);
            int r2 = sodium_hex2bin(peer_hash, sizeof(peer_hash),
                peer.hashid.c_str(), peer.hashid.size(), nullptr, &bin_len, nullptr);

            if (r1 != 0 || r2 != 0) {
                std::cout << peer.ip << ":" << peer.port << " -> INVALID (bad hex)\n";
            } else {
                bool ok = verifyHashId(peer_pk, peer_hash);
                std::cout << peer.ip << ":" << peer.port << " -> "
                          << (ok ? "VALID" : "INVALID") << '\n';
            }
        }

        std::cout << "Public Key: " << pk_hex << '\n';
        std::cout << "Hash ID   : " << hash_hex << '\n';
    }
    catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << '\n';
        return 1;
    }

    return 0;
}
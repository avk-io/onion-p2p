#include <bits/stdc++.h>
#include <asio.hpp>
#include <sodium.h>
#include <fstream>
#include <arpa/inet.h>
#include "peer.hpp"

using asio::ip::tcp;

// Connects to the relay, sends LIST, parses the count-prefixed response,
// and returns the Peer entry whose hashid matches target_hash_hex.
// Returns false if no match was found.
bool lookupPeerByHashId(
    asio::io_context& io,
    const std::string& relay_ip,
    const std::string& relay_port,
    const std::string& target_hash_hex,
    Peer& out_peer)
{
    tcp::resolver resolver(io);
    auto endpoints = resolver.resolve(relay_ip, relay_port);

    tcp::socket socket(io);
    asio::connect(socket, endpoints);

    asio::write(socket, asio::buffer(std::string("LIST\n")));

    asio::streambuf buf;
    std::error_code error;

    asio::read_until(socket, buf, '\n', error);
    if (error) throw std::system_error(error);

    std::istream is(&buf);
    std::string line;
    std::getline(is, line);
    int n = std::stoi(line);

    for (int i = 0; i < n; i++) {
        asio::read_until(socket, buf, '\n', error);
        if (error) throw std::system_error(error);

        std::getline(is, line);

        Peer peer;
        std::istringstream iss(line);
        iss >> peer.ip >> peer.port >> peer.pubkey >> peer.hashid;

        if (peer.hashid == target_hash_hex) {
            out_peer = peer;
            return true;
        }
    }

    return false;
}

int main(int argc, char* argv[]) {
    if (argc != 5) {
        std::cerr
            << "Usage: "
            << argv[0]
            << " <own_port> <own_keyfile> <relay_ip> <relay_port>\n";
        return 1;
    }
    unsigned short own_port = std::stoi(argv[1]);

    std::string own_keyfile = argv[2];
    std::string relay_ip = argv[3];
    std::string relay_port = argv[4];

    if (sodium_init() < 0)
        return 1;

    unsigned char p1_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char p1_sk[crypto_box_SECRETKEYBYTES];

    std::ifstream keyfile_in(own_keyfile, std::ios::binary);

    if (keyfile_in) {
        keyfile_in.read(reinterpret_cast<char*>(p1_pk), sizeof(p1_pk));
        keyfile_in.read(reinterpret_cast<char*>(p1_sk), sizeof(p1_sk));

        if (!keyfile_in) {
            std::cerr << "Failed to read key file\n";
            return 1;
        }
    } else {
        crypto_box_keypair(p1_pk, p1_sk);

        std::ofstream keyfile_out(own_keyfile, std::ios::binary);
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

    std::cout << "Node (" << own_port << ") Public Key:\n"
              << p1_pk_hex << "\n";

    unsigned char hash[crypto_generichash_BYTES];

    asio::io_context io;

    crypto_generichash(
        hash,
        sizeof(hash),
        p1_pk,
        sizeof(p1_pk),
        nullptr,
        0
    );

    char hash_hex[crypto_generichash_BYTES * 2 + 1];

    sodium_bin2hex(
        hash_hex,
        sizeof(hash_hex),
        hash,
        sizeof(hash)
    );

    tcp::resolver resolver(io);

    auto relay_endpoints =
        resolver.resolve(relay_ip, relay_port);

    tcp::socket relay_socket(io);

    asio::connect(
        relay_socket,
        relay_endpoints
    );

    std::string command =
        "REGISTER 127.0.0.1 " +
        std::to_string(own_port) +
        " " +
        std::string(p1_pk_hex) +
        " " +
        std::string(hash_hex) +
        "\n";

    asio::write(
        relay_socket,
        asio::buffer(command)
    );

    asio::streambuf reg_buf;
    std::error_code reg_error;

    asio::read_until(
        relay_socket,
        reg_buf,
        '\n',
        reg_error
    );

    if (reg_error)
        throw std::system_error(reg_error);

    std::istream reg_is(&reg_buf);

    std::string response;
    std::getline(reg_is, response);

    std::cout << "Relay server: "
              << response << '\n';

    // Registration connection is done with; let it close naturally when
    // relay_socket goes out of scope. Each lookup below opens a fresh
    // connection to the relay instead of reusing this one.

    tcp::acceptor acceptor(
        io,
        tcp::endpoint(tcp::v4(), own_port)
    );

    for (;;) {
        tcp::socket socket(io);
        acceptor.accept(socket);

        std::cout << "Incoming connection on port "
                  << own_port
                  << "\n";

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

        std::cout << "Next hop HashId: "
                  << next_hash_hex << "\n";

        // Look up the next hop's ip/port from the relay using its hashid
        Peer next_peer;
        bool found;

        try {
            found = lookupPeerByHashId(
                io,
                relay_ip,
                relay_port,
                std::string(next_hash_hex),
                next_peer
            );
        }
        catch (const std::exception& e) {
            std::cerr << "Relay lookup failed: " << e.what() << "\n";
            continue;
        }

        if (!found) {
            std::cerr << "Unknown next hop hashid, dropping packet: "
                      << next_hash_hex << "\n";
            continue;
        }

        std::cout << "Resolved next hop to "
                  << next_peer.ip << ":" << next_peer.port << "\n";

        // Connect to the resolved next hop
        tcp::resolver next_resolver(io);
        auto next_endpoints =
            next_resolver.resolve(next_peer.ip, next_peer.port);

        tcp::socket next_socket(io);

        asio::connect(
            next_socket,
            next_endpoints
        );

        // Send remaining blob
        uint32_t out_len = static_cast<uint32_t>(remaining_blob.size());
        uint32_t out_len_net = htonl(out_len);

        asio::write(
            next_socket,
            asio::buffer(&out_len_net, sizeof(out_len_net))
        );

        asio::write(
            next_socket,
            asio::buffer(remaining_blob)
        );

        std::cout << "Forwarded packet to "
                  << next_peer.ip
                  << ":"
                  << next_peer.port
                  << "\n";
    }

    return 0;
}
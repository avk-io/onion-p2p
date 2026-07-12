#include "httplib.h"
#include <sodium.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <cstdio>

bool load_or_generate_keypair(
    const std::string& path,
    unsigned char pk[crypto_box_PUBLICKEYBYTES],
    unsigned char sk[crypto_box_SECRETKEYBYTES])
{
    namespace fs = std::filesystem;

    if (fs::exists(path)) {
        std::ifstream in(path, std::ios::binary);
        if (!in)
            return false;

        in.read(reinterpret_cast<char*>(pk), crypto_box_PUBLICKEYBYTES);
        in.read(reinterpret_cast<char*>(sk), crypto_box_SECRETKEYBYTES);

        return in.good();
    }

    crypto_box_keypair(pk, sk);

    std::ofstream out(path, std::ios::binary);
    if (!out)
        return false;

    out.write(reinterpret_cast<const char*>(pk), crypto_box_PUBLICKEYBYTES);
    out.write(reinterpret_cast<const char*>(sk), crypto_box_SECRETKEYBYTES);

    return out.good();
}

// Temporary hardcoded relay directory: hashid (hex) -> {ip, port}.
// Real version later reads this from a config file instead.

std::mutex mailbox_mutex;
std::map<std::string, std::vector<std::string>> mailbox;

struct RelayAddr { std::string ip; std::string port; };
std::map<std::string, RelayAddr> relay_directory = {
    { "f58bc6eaad5b76449451abcd2c079b3b171f2ae82d65f73cbcedc22e3968de08", {"127.0.0.1", "8081"} },
    { "c182b4305a9dd333d5053652f68180fd3d5603a6e97fb1c7258d448e6486ef4a", {"127.0.0.1", "8082"} },
    { "ae5a05b449d25057f615f2383c931359066ffe5ef3b8e0b3e0fbe359b376eff8", {"127.0.0.1", "8083"} },
};

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0]
                  << " <http_port> <keyfile>\n";
        return 1;
    }

    int http_port = std::stoi(argv[1]);
    std::string keyfile_path = argv[2];

    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize libsodium\n";
        return 1;
    }

    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    unsigned char sk[crypto_box_SECRETKEYBYTES];

    if (!load_or_generate_keypair(keyfile_path, pk, sk)) {
        std::cerr << "Failed to load/generate keypair\n";
        return 1;
    }

    char pk_hex[crypto_box_PUBLICKEYBYTES * 2 + 1];
    sodium_bin2hex(pk_hex, sizeof(pk_hex), pk, sizeof(pk));

    unsigned char hash[crypto_generichash_BYTES];
    crypto_generichash(hash, sizeof(hash), pk, sizeof(pk), nullptr, 0);

    char hash_hex[crypto_generichash_BYTES * 2 + 1];
    sodium_bin2hex(hash_hex, sizeof(hash_hex), hash, sizeof(hash));

    std::cout << "Relay pubkey: " << pk_hex << "\n";
    std::cout << "Relay hashid: " << hash_hex << "\n";

    httplib::Server svr;

    svr.Get(R"(/mailbox/([a-f0-9]+))", [&](const httplib::Request& req, httplib::Response& res) {
        std::string hashid = req.matches[1];

        std::lock_guard<std::mutex> lock(mailbox_mutex);

        auto it = mailbox.find(hashid);
        if (it == mailbox.end() || it->second.empty()) {
            res.status = 200;
            res.set_content("[]", "application/json");
            return;
        }

        std::string json = "[";
        for (size_t i = 0; i < it->second.size(); i++) {
            if (i > 0) json += ",";
            json += "\"" + it->second[i] + "\"";
        }
        json += "]";

        res.set_content(json, "application/json");
        it->second.clear();   // mark as delivered
    });

    svr.Post("/relay/deliver",
             [&](const httplib::Request& req, httplib::Response& res) {

        // -------------------------------
        // Decode Base64
        // -------------------------------
        std::vector<unsigned char> sealed_blob(req.body.size());

        size_t decoded_len = 0;

        if (sodium_base642bin(
                sealed_blob.data(),
                sealed_blob.size(),
                req.body.c_str(),
                req.body.size(),
                nullptr,
                &decoded_len,
                nullptr,
                sodium_base64_VARIANT_ORIGINAL) != 0) {

            res.status = 400;
            res.set_content("Invalid Base64", "text/plain");
            return;
        }

        sealed_blob.resize(decoded_len);

        if (sealed_blob.size() < crypto_box_SEALBYTES) {
            res.status = 400;
            res.set_content("Ciphertext too small", "text/plain");
            return;
        }

        // -------------------------------
        // Decrypt sealed box
        // -------------------------------
        std::vector<unsigned char> layer_plaintext(
            sealed_blob.size() - crypto_box_SEALBYTES);

        if (crypto_box_seal_open(
                layer_plaintext.data(),
                sealed_blob.data(),
                sealed_blob.size(),
                pk,
                sk) != 0) {

            res.status = 400;
            res.set_content("Decryption failed", "text/plain");
            return;
        }

        // -------------------------------
        // Parse layer
        // -------------------------------
        if (layer_plaintext.size() < 33) {
            res.status = 400;
            res.set_content("Malformed layer", "text/plain");
            return;
        }

        unsigned char layer_type = layer_plaintext[0];

        std::vector<unsigned char> next_hashid(
            layer_plaintext.begin() + 1,
            layer_plaintext.begin() + 33);

        std::vector<unsigned char> remaining(
            layer_plaintext.begin() + 33,
            layer_plaintext.end());

        // -------------------------------
        // Print decoded info
        // -------------------------------
        char next_hashid_hex[65];
        for (size_t i = 0; i < next_hashid.size(); i++)
            std::snprintf(next_hashid_hex + i * 2, 3, "%02x", next_hashid[i]);
        next_hashid_hex[64] = '\0';

        std::cout << "\n===== Onion Layer Received =====\n";
        std::cout << "Layer Type: " << static_cast<int>(layer_type) << '\n';
        std::cout << "Next HashID: " << next_hashid_hex << '\n';
        std::cout << "Remaining Payload: " << remaining.size() << " bytes\n";

        // -------------------------------
        // Forward to a known relay, or deliver to mailbox if next_hashid
        // isn't a relay we know about (meaning it's an ordinary recipient).
        //
        // Every layer a relay successfully peels is always layer_type
        // 0x00 (relay-forward) -- the final layer is sealed for the
        // RECIPIENT's key, not any relay's, so a relay can never
        // successfully open it. There is no separate 0x01 case to
        // handle here.
        // -------------------------------
        auto it = relay_directory.find(next_hashid_hex);

        if (it != relay_directory.end()) {
            // Known relay -- forward the still-sealed blob onward, unchanged.
            size_t fwd_b64_len = sodium_base64_ENCODED_LEN(
                remaining.size(), sodium_base64_VARIANT_ORIGINAL);
            std::vector<char> fwd_b64(fwd_b64_len);

            sodium_bin2base64(
                fwd_b64.data(), fwd_b64.size(),
                remaining.data(), remaining.size(),
                sodium_base64_VARIANT_ORIGINAL
            );

            httplib::Client next_hop_client(it->second.ip, std::stoi(it->second.port));
            auto fwd_res = next_hop_client.Post("/relay/deliver", fwd_b64.data(), "text/plain");

            if (!fwd_res || fwd_res->status != 200) {
                std::cout << "Forward to " << it->second.ip << ":" << it->second.port
                          << " failed\n";
                std::cout << "================================\n";
                res.status = 502;
                res.set_content("Forward failed", "text/plain");
                return;
            }

            std::cout << "Forwarded to " << it->second.ip << ":" << it->second.port << "\n";
        }
        else {
            // Not a known relay -- must be an ordinary recipient. Store
            // the still-sealed blob directly in our local mailbox.
            size_t mb_b64_len = sodium_base64_ENCODED_LEN(
                remaining.size(), sodium_base64_VARIANT_ORIGINAL);
            std::vector<char> mb_b64(mb_b64_len);

            sodium_bin2base64(
                mb_b64.data(), mb_b64.size(),
                remaining.data(), remaining.size(),
                sodium_base64_VARIANT_ORIGINAL
            );

            {
                std::lock_guard<std::mutex> lock(mailbox_mutex);
                mailbox[next_hashid_hex].push_back(mb_b64.data());
            }

            std::cout << "Delivered to mailbox for " << next_hashid_hex << "\n";
        }

        std::cout << "================================\n";

        res.status = 200;
        res.set_content("OK", "text/plain");
    });

    std::cout << "Relay hop listening on port " << http_port << '\n';

    svr.listen("127.0.0.1", http_port);

    return 0;
}
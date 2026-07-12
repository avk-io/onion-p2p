#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"
#include <sodium.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <random>
#include <algorithm>
#include <cstdio>

bool load_or_generate_keypair(
    const std::string& path,
    unsigned char pk[crypto_box_PUBLICKEYBYTES],
    unsigned char sk[crypto_box_SECRETKEYBYTES])
{
    namespace fs = std::filesystem;

    if (fs::exists(path)) {
        std::ifstream in(path, std::ios::binary);
        if (!in) return false;

        in.read(reinterpret_cast<char*>(pk), crypto_box_PUBLICKEYBYTES);
        in.read(reinterpret_cast<char*>(sk), crypto_box_SECRETKEYBYTES);

        return in.good();
    }

    crypto_box_keypair(pk, sk);

    std::ofstream out(path, std::ios::binary);
    if (!out) return false;

    out.write(reinterpret_cast<const char*>(pk), crypto_box_PUBLICKEYBYTES);
    out.write(reinterpret_cast<const char*>(sk), crypto_box_SECRETKEYBYTES);

    return out.good();
}

// Fixed set of relay servers this daemon knows about. In a real
// deployment this would come from a config file; hardcoded here since
// Option A means relay hops are a small, operator-controlled set, not
// discovered dynamically.
struct RelayAddr {
    std::string ip;
    std::string port;
    std::string pubkey_hex;
    std::string hashid_hex;
};

std::vector<RelayAddr> known_relays = {
    { "127.0.0.1", "8081",
      "3b6bf21b2b261cb04d29c6a0a8eaeaa64aebc0aee1fb7efb4eb0cb4385ce0f6d",
      "f58bc6eaad5b76449451abcd2c079b3b171f2ae82d65f73cbcedc22e3968de08" },
    { "127.0.0.1", "8082",
      "95738bbedcbe1332afc8234f7778158cdfcd8d8a62c67fa225a7de53a646e46a",
      "c182b4305a9dd333d5053652f68180fd3d5603a6e97fb1c7258d448e6486ef4a" },
    { "127.0.0.1", "8083",
      "274106e312572dfdda19dcda3e45612f455229f38a30e5cabf0899c0984e2e53",
      "ae5a05b449d25057f615f2383c931359066ffe5ef3b8e0b3e0fbe359b376eff8" },
};

unsigned char g_pk[crypto_box_PUBLICKEYBYTES];
unsigned char g_sk[crypto_box_SECRETKEYBYTES];
char g_pk_hex[crypto_box_PUBLICKEYBYTES * 2 + 1];
char g_hash_hex[crypto_generichash_BYTES * 2 + 1];
unsigned char g_hash[crypto_generichash_BYTES];

// Splits body on '|' -- placeholder wire format until real JSON parsing
// is added. Expected: recipient_hashid|recipient_pubkey_hex|message
bool parseSendBody(
    const std::string& body,
    std::string& recipient_hashid,
    std::string& recipient_pubkey_hex,
    std::string& message)
{
    size_t first = body.find('|');
    if (first == std::string::npos) return false;

    size_t second = body.find('|', first + 1);
    if (second == std::string::npos) return false;

    recipient_hashid = body.substr(0, first);
    recipient_pubkey_hex = body.substr(first + 1, second - first - 1);
    message = body.substr(second + 1);

    return !recipient_hashid.empty() && !recipient_pubkey_hex.empty();
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <daemon_http_port> <keyfile>\n";
        return 1;
    }

    int daemon_port = std::stoi(argv[1]);
    std::string keyfile_path = argv[2];

    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize libsodium\n";
        return 1;
    }

    if (!load_or_generate_keypair(keyfile_path, g_pk, g_sk)) {
        std::cerr << "Failed to load/generate keypair\n";
        return 1;
    }

    sodium_bin2hex(g_pk_hex, sizeof(g_pk_hex), g_pk, sizeof(g_pk));

    crypto_generichash(g_hash, sizeof(g_hash), g_pk, sizeof(g_pk), nullptr, 0);
    sodium_bin2hex(g_hash_hex, sizeof(g_hash_hex), g_hash, sizeof(g_hash));

    httplib::SSLServer svr("relay.crt","relay.key");

    svr.Get("/identity", [&](const httplib::Request&, httplib::Response& res) {
        std::string json =
            "{\"pubkey\":\"" + std::string(g_pk_hex) +
            "\",\"hashid\":\"" + std::string(g_hash_hex) + "\"}";
        res.set_content(json, "application/json");
    });

    svr.Get("/inbox", [&](const httplib::Request&, httplib::Response& res) {
    std::vector<std::string> decrypted_messages;   // will hold formatted "sender: message" strings

    for (const auto& relay : known_relays) {
        httplib::SSLClient relay_client(relay.ip, std::stoi(relay.port));
        relay_client.enable_server_certificate_verification(false);
        auto mailbox_res = relay_client.Get(("/mailbox/" + std::string(g_hash_hex)).c_str());

      
        if (!mailbox_res || mailbox_res->status != 200) continue;

        // Very simple manual parse of a JSON array of quoted strings:
        // ["abc==","def=="]  ->  {"abc==", "def=="}
        const std::string& body = mailbox_res->body;
        size_t pos = 1;   // skip leading '['
        while (pos < body.size() && body[pos] != ']') {
            if (body[pos] == '"') {
                size_t end = body.find('"', pos + 1);
                if (end == std::string::npos) break;

                std::string b64_payload = body.substr(pos + 1, end - pos - 1);
                pos = end + 1;

                // decode + decrypt this one payload
                std::vector<unsigned char> sealed(b64_payload.size());
                size_t decoded_len = 0;
                if (sodium_base642bin(
                        sealed.data(), sealed.size(),
                        b64_payload.c_str(), b64_payload.size(),
                        nullptr, &decoded_len, nullptr,
                        sodium_base64_VARIANT_ORIGINAL) != 0) {
                    continue;
                }
                sealed.resize(decoded_len);

                if (sealed.size() < crypto_box_SEALBYTES) continue;

                std::vector<unsigned char> plaintext(sealed.size() - crypto_box_SEALBYTES);
                if (crypto_box_seal_open(plaintext.data(), sealed.data(), sealed.size(), g_pk, g_sk) != 0) {
                    continue;   // not actually for us, or corrupted
                }

                if (plaintext.size() < 1 + crypto_generichash_BYTES*2) continue;

                char sender_hex[crypto_generichash_BYTES * 2 + 1];
                sodium_bin2hex(sender_hex, sizeof(sender_hex), plaintext.data()+1, crypto_generichash_BYTES);

                std::string message(
                    reinterpret_cast<char*>(plaintext.data()+ 1 + crypto_generichash_BYTES*2),
                    plaintext.size() - 1 - crypto_generichash_BYTES*2
                );

                decrypted_messages.push_back(std::string(sender_hex) + ": " + message);
            } else {
                pos++;
            }
        }
    }

    std::string json = "[";
    for (size_t i = 0; i < decrypted_messages.size(); i++) {
        if (i > 0) json += ",";
        json += "\"" + decrypted_messages[i] + "\"";
    }
    json += "]";

    res.set_content(json, "application/json");
});

    svr.Post("/send", [&](const httplib::Request& req, httplib::Response& res) {
        std::string recipient_hashid, recipient_pubkey_hex, message;

        if (!parseSendBody(req.body, recipient_hashid, recipient_pubkey_hex, message)) {
            res.status = 400;
            res.set_content("Expected body: recipient_hashid|recipient_pubkey_hex|message", "text/plain");
            return;
        }

        if (known_relays.size() < 3) {
            res.status = 500;
            res.set_content("Not enough known relays configured", "text/plain");
            return;
        }

        

        // Decode recipient pubkey and hashid bytes.
        unsigned char recipient_pk[crypto_box_PUBLICKEYBYTES];
        unsigned char recipient_hash_bytes[crypto_generichash_BYTES];
        size_t bin_len;

        bool ok =
            sodium_hex2bin(recipient_pk, sizeof(recipient_pk),
                recipient_pubkey_hex.c_str(), recipient_pubkey_hex.size(),
                nullptr, &bin_len, nullptr) == 0 &&
            sodium_hex2bin(recipient_hash_bytes, sizeof(recipient_hash_bytes),
                recipient_hashid.c_str(), recipient_hashid.size(),
                nullptr, &bin_len, nullptr) == 0;

        if (!ok) {
            res.status = 400;
            res.set_content("Invalid recipient hex fields", "text/plain");
            return;
        }

        // Pick 3 distinct relays from the known, fixed set.
        std::vector<RelayAddr> chosen;
        std::sample(
            known_relays.begin(), known_relays.end(),
            std::back_inserter(chosen),
            3,
            std::mt19937{std::random_device{}()}
        );

        RelayAddr& r1 = chosen[0];
        RelayAddr& r2 = chosen[1];
        RelayAddr& r3 = chosen[2];

        unsigned char r1_pk[crypto_box_PUBLICKEYBYTES];
        unsigned char r2_pk[crypto_box_PUBLICKEYBYTES];
        unsigned char r3_pk[crypto_box_PUBLICKEYBYTES];

        sodium_hex2bin(r1_pk, sizeof(r1_pk), r1.pubkey_hex.c_str(), r1.pubkey_hex.size(), nullptr, &bin_len, nullptr);
        sodium_hex2bin(r2_pk, sizeof(r2_pk), r2.pubkey_hex.c_str(), r2.pubkey_hex.size(), nullptr, &bin_len, nullptr);
        sodium_hex2bin(r3_pk, sizeof(r3_pk), r3.pubkey_hex.c_str(), r3.pubkey_hex.size(), nullptr, &bin_len, nullptr);

        unsigned char r2_hash[crypto_generichash_BYTES];
        unsigned char r3_hash[crypto_generichash_BYTES];

        sodium_hex2bin(r2_hash, sizeof(r2_hash), r2.hashid_hex.c_str(), r2.hashid_hex.size(), nullptr, &bin_len, nullptr);
        sodium_hex2bin(r3_hash, sizeof(r3_hash), r3.hashid_hex.c_str(), r3.hashid_hex.size(), nullptr, &bin_len, nullptr);

        // ---- Layer 4 (innermost, final, for recipient) ----
        // sender_hashid(32) + recipient_hashid(32) + message
        std::vector<unsigned char> plaintext_final;
        plaintext_final.push_back(0x01);
        plaintext_final.insert(plaintext_final.end(), g_hash, g_hash + crypto_generichash_BYTES);
        plaintext_final.insert(plaintext_final.end(), recipient_hash_bytes, recipient_hash_bytes + crypto_generichash_BYTES);
        plaintext_final.insert(plaintext_final.end(), message.begin(), message.end());

        std::vector<unsigned char> sealed_final(plaintext_final.size() + crypto_box_SEALBYTES);
        crypto_box_seal(sealed_final.data(), plaintext_final.data(), plaintext_final.size(), recipient_pk);

        // ---- Layer 3 (for r3): hash(recipient) + sealed_final ----
        std::vector<unsigned char> plaintext_r3;
        plaintext_r3.push_back(0x00);
        plaintext_r3.insert(plaintext_r3.end(), recipient_hash_bytes, recipient_hash_bytes + crypto_generichash_BYTES);
        plaintext_r3.insert(plaintext_r3.end(), sealed_final.begin(), sealed_final.end());

        std::vector<unsigned char> sealed_r3(plaintext_r3.size() + crypto_box_SEALBYTES);
        crypto_box_seal(sealed_r3.data(), plaintext_r3.data(), plaintext_r3.size(), r3_pk);

        // ---- Layer 2 (for r2): hash(r3) + sealed_r3 ----
        std::vector<unsigned char> plaintext_r2;
        plaintext_r2.push_back(0x00);
        plaintext_r2.insert(plaintext_r2.end(), r3_hash, r3_hash + crypto_generichash_BYTES);
        plaintext_r2.insert(plaintext_r2.end(), sealed_r3.begin(), sealed_r3.end());

        std::vector<unsigned char> sealed_r2(plaintext_r2.size() + crypto_box_SEALBYTES);
        crypto_box_seal(sealed_r2.data(), plaintext_r2.data(), plaintext_r2.size(), r2_pk);

        // ---- Layer 1 (outermost, for r1): hash(r2) + sealed_r2 ----
        std::vector<unsigned char> plaintext_r1;
        plaintext_r1.push_back(0x00);
        plaintext_r1.insert(plaintext_r1.end(), r2_hash, r2_hash + crypto_generichash_BYTES);
        plaintext_r1.insert(plaintext_r1.end(), sealed_r2.begin(), sealed_r2.end());

        std::vector<unsigned char> sealed_r1(plaintext_r1.size() + crypto_box_SEALBYTES);
        crypto_box_seal(sealed_r1.data(), plaintext_r1.data(), plaintext_r1.size(), r1_pk);

        // ---- base64-encode and POST to r1 ----
        size_t b64_len = sodium_base64_ENCODED_LEN(sealed_r1.size(), sodium_base64_VARIANT_ORIGINAL);
        std::vector<char> b64(b64_len);
        sodium_bin2base64(b64.data(), b64.size(), sealed_r1.data(), sealed_r1.size(), sodium_base64_VARIANT_ORIGINAL);

        httplib::SSLClient relay_client(r1.ip, std::stoi(r1.port));
        relay_client.enable_server_certificate_verification(false);
        auto relay_res = relay_client.Post("/relay/deliver", b64.data(), "text/plain");

        if (!relay_res || relay_res->status != 200) {
            std::cerr << "Relay POST failed.";
            if(relay_res){
                std::cerr<< "Status: " << relay_res->status << ", body: "<< relay_res->body<<"\n";
            }else{
                std::cerr<<"No Response (connection-level failure): "
                        << httplib::to_string(relay_res.error())<<"\n";
            }
            res.status = 502;
            res.set_content("Failed to reach first relay hop", "text/plain");
            return;
        }

        std::string summary = "Sent via " + r1.hashid_hex.substr(0, 8) + "->"
                             + r2.hashid_hex.substr(0, 8) + "->"
                             + r3.hashid_hex.substr(0, 8);

        res.status = 200;
        res.set_content(summary, "text/plain");
    });

    std::cout << "Daemon listening on port " << daemon_port
              << ", hashid " << g_hash_hex << "\n";

    svr.listen("127.0.0.1", daemon_port);

    return 0;
}
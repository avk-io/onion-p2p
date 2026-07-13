#define CPPHTTPLIB_OPENSSL_SUPPORT
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
#include <sqlite3.h>
#include <chrono>
#include <unordered_map>
#include <algorithm>

sqlite3* db = nullptr;

bool init_db(const std::string& path) {
    if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) {
        std::cerr << "Failed to open database: " << sqlite3_errmsg(db) << "\n";
        return false;
    }

    const char* create_sql =
        "CREATE TABLE IF NOT EXISTS mailbox ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "recipient_hashid TEXT NOT NULL,"
        "payload_b64 TEXT NOT NULL,"
        "created_at INTEGER NOT NULL"
        ");";

    char* err_msg = nullptr;
    if (sqlite3_exec(db, create_sql, nullptr, nullptr, &err_msg) != SQLITE_OK) {
        std::cerr << "Failed to create table: " << err_msg << "\n";
        sqlite3_free(err_msg);
        return false;
    }

    return true;
}

std::mutex rate_limit_mutex;
std::unordered_map<std::string,std::vector<std::chrono::steady_clock::time_point>> request_log;

const int RATE_LIMIT_MAX_REQUESTS = 20;
const int RATE_LIMIT_WINDOW_SECONDS = 10;

bool is_rate_limited(const std::string& client_ip){
    auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(rate_limit_mutex);

    auto& timestamps = request_log[client_ip];

    timestamps.erase(
        std::remove_if(timestamps.begin(),timestamps.end(),
            [&](const auto& t){
                return std::chrono::duration_cast<std::chrono::seconds>(now-t).count() > RATE_LIMIT_WINDOW_SECONDS;
            }),
        timestamps.end()
    );
    if(timestamps.size()>=RATE_LIMIT_MAX_REQUESTS){
        return true;
    }
    timestamps.push_back(now);
    return false;
}
bool mailbox_store(const std::string& recipient_hashid, const std::string& payload_b64) {
    const char* sql = "INSERT INTO mailbox (recipient_hashid, payload_b64, created_at) VALUES (?, ?, ?);";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;

    sqlite3_bind_text(stmt, 1, recipient_hashid.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, payload_b64.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)time(nullptr));

    bool ok = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return ok;
}

std::vector<std::string> mailbox_fetch_and_clear(const std::string& recipient_hashid) {
    std::vector<std::string> results;

    const char* select_sql = "SELECT payload_b64 FROM mailbox WHERE recipient_hashid = ?;";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db, select_sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, recipient_hashid.c_str(), -1, SQLITE_TRANSIENT);

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char* text = sqlite3_column_text(stmt, 0);
            results.push_back(reinterpret_cast<const char*>(text));
        }
    }
    sqlite3_finalize(stmt);

    const char* delete_sql = "DELETE FROM mailbox WHERE recipient_hashid = ?;";
    if (sqlite3_prepare_v2(db, delete_sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, recipient_hashid.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
    }
    sqlite3_finalize(stmt);

    return results;
}

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

    if (!init_db("relay_mailbox_" + std::to_string(http_port) + ".db")) {
        std::cerr << "Failed to initialize mailbox database\n";
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

    httplib::SSLServer svr("relay.crt","relay.key");

    svr.Get(R"(/mailbox/([a-f0-9]+))", [&](const httplib::Request& req, httplib::Response& res) {
        std::string hashid = req.matches[1];

        std::vector<std::string> results = mailbox_fetch_and_clear(hashid);

        std::string json = "[";
        for (size_t i = 0; i < results.size(); i++) {
            if (i > 0) json += ",";
            json += "\"" + results[i] + "\"";
        }
        json += "]";

        res.set_content(json, "application/json");
    });

    svr.Post("/relay/deliver",
             [&](const httplib::Request& req, httplib::Response& res) {

                if(is_rate_limited(req.remote_addr)){
                    res.status = 429;
                    res.set_content("Too many requests","text/plain");
                    return;
                }
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

            httplib::SSLClient next_hop_client(it->second.ip, std::stoi(it->second.port));
            next_hop_client.enable_server_certificate_verification(false);
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
            mailbox_store(next_hashid_hex,mb_b64.data());
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
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"
#include <sodium.h>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <random>
#include <algorithm>
#include <cstdio>
#include <chrono>
#include <unordered_map>
#include <ctime>
#include <curl/curl.h>

void log(const std::string& level, const std::string& message) {
    std::time_t now = std::time(nullptr);
    char timebuf[32];
    std::strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", std::localtime(&now));

    std::cout << "[" << timebuf << "] [" << level << "] " << message << "\n";
}

std::mutex rate_limit_mutex;
std::unordered_map<std::string, std::vector<std::chrono::steady_clock::time_point>> request_log;

const int RATE_LIMIT_MAX_REQUESTS = 20;
const int RATE_LIMIT_WINDOW_SECONDS = 10;

bool is_rate_limited(const std::string& client_ip) {
    auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(rate_limit_mutex);

    auto& timestamps = request_log[client_ip];

    timestamps.erase(
        std::remove_if(timestamps.begin(), timestamps.end(),
            [&](const auto& t) {
                return std::chrono::duration_cast<std::chrono::seconds>(now - t).count() > RATE_LIMIT_WINDOW_SECONDS;
            }),
        timestamps.end()
    );
    if (timestamps.size() >= RATE_LIMIT_MAX_REQUESTS) return true;

    timestamps.push_back(now);
    return false;
}

// Fixed set of relay servers, reachable as Tor hidden services. This
// daemon is now a shared, stateless piece of infrastructure -- it never
// holds any individual user's keys. Every request carries whatever
// identity info it needs (sender hashid to seal with, recipient info to
// address the packet, or a hashid to poll a mailbox for).
struct RelayAddr {
    std::string onion_host;
    std::string port;
    std::string pubkey_hex;
    std::string hashid_hex;
};

std::vector<RelayAddr> known_relays = {
    { "tbheffnwzhvl2p6k3rcesvy4k7njiafk4x7dvxcdpvabulqbuldphcad.onion", "8081",
      "3b6bf21b2b261cb04d29c6a0a8eaeaa64aebc0aee1fb7efb4eb0cb4385ce0f6d",
      "f58bc6eaad5b76449451abcd2c079b3b171f2ae82d65f73cbcedc22e3968de08" },
    { "diwn2yea7elxobibz4cm6s7glvxxtno3nh7ocor5ofrnouvnynv6isad.onion", "8082",
      "95738bbedcbe1332afc8234f7778158cdfcd8d8a62c67fa225a7de53a646e46a",
      "c182b4305a9dd333d5053652f68180fd3d5603a6e97fb1c7258d448e6486ef4a" },
    { "aaeqqfkdhf5xmhwu2beg4cxl7orpqnw244a3cugkii5nwr4j3inewpid.onion", "8083",
      "274106e312572dfdda19dcda3e45612f455229f38a30e5cabf0899c0984e2e53",
      "ae5a05b449d25057f615f2383c931359066ffe5ef3b8e0b3e0fbe359b376eff8" },
};

// Splits body on '|'. New format includes sender_hashid up front, since
// the daemon has no identity of its own to fall back on:
// sender_hashid|recipient_hashid|recipient_pubkey_hex|message
bool parseSendBody(
    const std::string& body,
    std::string& sender_hashid,
    std::string& recipient_hashid,
    std::string& recipient_pubkey_hex,
    std::string& message)
{
    size_t p1 = body.find('|');
    if (p1 == std::string::npos) return false;

    size_t p2 = body.find('|', p1 + 1);
    if (p2 == std::string::npos) return false;

    size_t p3 = body.find('|', p2 + 1);
    if (p3 == std::string::npos) return false;

    sender_hashid = body.substr(0, p1);
    recipient_hashid = body.substr(p1 + 1, p2 - p1 - 1);
    recipient_pubkey_hex = body.substr(p2 + 1, p3 - p2 - 1);
    message = body.substr(p3 + 1);

    return !sender_hashid.empty() && !recipient_hashid.empty() && !recipient_pubkey_hex.empty();
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        log("ERROR", std::string("Usage: ") + argv[0] + " <daemon_http_port>");
        return 1;
    }

    int daemon_port = std::stoi(argv[1]);

    if (sodium_init() < 0) {
        log("ERROR", "Failed to initialize libsodium");
        return 1;
    }

    httplib::SSLServer svr("relay.crt", "relay.key");

    // Returns raw, still-sealed base64 blobs for the given hashid --
    // NO decryption happens here. The daemon has no private keys to
    // decrypt with; the caller (browser, holding the key locally) is
    // responsible for calling crypto_box_seal_open itself.
    svr.Get("/inbox", [&](const httplib::Request& req, httplib::Response& res) {
        if (is_rate_limited(req.remote_addr)) {
            log("WARN", "Rate limit exceeded for " + req.remote_addr + " on /inbox");
            res.status = 429;
            res.set_content("Too many requests", "text/plain");
            return;
        }

        if (!req.has_param("hashid")) {
            res.status = 400;
            res.set_content("Missing hashid query parameter", "text/plain");
            return;
        }
        std::string hashid = req.get_param_value("hashid");

        std::vector<std::string> raw_sealed_blobs;

        for (const auto& relay : known_relays) {
            CURL* curl = curl_easy_init();
            if (!curl) continue;

            std::string url = "https://" + relay.onion_host + ":" + relay.port + "/mailbox/" + hashid;
            std::string curl_response;
            long http_code = 0;

            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_PROXY, "socks5h://127.0.0.1:9050");
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
                +[](void* contents, size_t size, size_t nmemb, std::string* out) -> size_t {
                    out->append(static_cast<char*>(contents), size * nmemb);
                    return size * nmemb;
                });
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &curl_response);

            CURLcode curl_res = curl_easy_perform(curl);
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
            curl_easy_cleanup(curl);

            if (curl_res != CURLE_OK || http_code != 200) continue;

            // Manual parse of a JSON array of quoted base64 strings:
            // ["abc==","def=="]  ->  push each string as-is, undecoded.
            const std::string& body = curl_response;
            size_t pos = 1;
            while (pos < body.size() && body[pos] != ']') {
                if (body[pos] == '"') {
                    size_t end = body.find('"', pos + 1);
                    if (end == std::string::npos) break;

                    raw_sealed_blobs.push_back(body.substr(pos + 1, end - pos - 1));
                    pos = end + 1;
                } else {
                    pos++;
                }
            }
        }

        log("INFO", "Inbox check for " + hashid + " returned "
            + std::to_string(raw_sealed_blobs.size()) + " raw sealed message(s)");

        std::string json = "[";
        for (size_t i = 0; i < raw_sealed_blobs.size(); i++) {
            if (i > 0) json += ",";
            json += "\"" + raw_sealed_blobs[i] + "\"";
        }
        json += "]";

        res.set_content(json, "application/json");
    });

    svr.Post("/send", [&](const httplib::Request& req, httplib::Response& res) {
        if (is_rate_limited(req.remote_addr)) {
            log("WARN", "Rate limit exceeded for " + req.remote_addr + " on /send");
            res.status = 429;
            res.set_content("Too many requests", "text/plain");
            return;
        }

        std::string sender_hashid, recipient_hashid, recipient_pubkey_hex, message;

        if (!parseSendBody(req.body, sender_hashid, recipient_hashid, recipient_pubkey_hex, message)) {
            res.status = 400;
            res.set_content(
                "Expected body: sender_hashid|recipient_hashid|recipient_pubkey_hex|message",
                "text/plain");
            return;
        }

        if (known_relays.size() < 3) {
            log("ERROR", "Not enough known relays configured");
            res.status = 500;
            res.set_content("Not enough known relays configured", "text/plain");
            return;
        }

        // Sender's identity here is JUST their hashid -- a public,
        // non-secret value the caller already knows about themselves.
        // No private key is needed to build the outer layers; sealing
        // only ever requires the RECIPIENT's public key at each step.
        unsigned char sender_hash_bytes[crypto_generichash_BYTES];
        unsigned char recipient_pk[crypto_box_PUBLICKEYBYTES];
        unsigned char recipient_hash_bytes[crypto_generichash_BYTES];
        size_t bin_len;

        bool ok =
            sodium_hex2bin(sender_hash_bytes, sizeof(sender_hash_bytes),
                sender_hashid.c_str(), sender_hashid.size(),
                nullptr, &bin_len, nullptr) == 0 &&
            sodium_hex2bin(recipient_pk, sizeof(recipient_pk),
                recipient_pubkey_hex.c_str(), recipient_pubkey_hex.size(),
                nullptr, &bin_len, nullptr) == 0 &&
            sodium_hex2bin(recipient_hash_bytes, sizeof(recipient_hash_bytes),
                recipient_hashid.c_str(), recipient_hashid.size(),
                nullptr, &bin_len, nullptr) == 0;

        if (!ok) {
            res.status = 400;
            res.set_content("Invalid hex fields", "text/plain");
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
        plaintext_final.insert(plaintext_final.end(), sender_hash_bytes, sender_hash_bytes + crypto_generichash_BYTES);
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

        // ---- base64-encode and POST to r1, through Tor ----
        size_t b64_len = sodium_base64_ENCODED_LEN(sealed_r1.size(), sodium_base64_VARIANT_ORIGINAL);
        std::vector<char> b64(b64_len);
        sodium_bin2base64(b64.data(), b64.size(), sealed_r1.data(), sealed_r1.size(), sodium_base64_VARIANT_ORIGINAL);

        CURL* curl = curl_easy_init();
        if (!curl) {
            log("ERROR", "Failed to initialize libcurl");
            res.status = 500;
            res.set_content("Internal error", "text/plain");
            return;
        }

        std::string url = "https://" + r1.onion_host + ":" + r1.port + "/relay/deliver";
        std::string curl_response;
        long http_code = 0;

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_PROXY, "socks5h://127.0.0.1:9050");
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, b64.data());
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
            +[](void* contents, size_t size, size_t nmemb, std::string* out) -> size_t {
                out->append(static_cast<char*>(contents), size * nmemb);
                return size * nmemb;
            });
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &curl_response);

        CURLcode curl_res = curl_easy_perform(curl);
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        curl_easy_cleanup(curl);

        if (curl_res != CURLE_OK || http_code != 200) {
            log("WARN", "Relay POST via Tor failed: " + std::string(curl_easy_strerror(curl_res))
                + ", status=" + std::to_string(http_code));
            res.status = 502;
            res.set_content("Failed to reach first relay hop", "text/plain");
            return;
        }

        std::string summary = "Sent via " + r1.hashid_hex.substr(0, 8) + "->"
                             + r2.hashid_hex.substr(0, 8) + "->"
                             + r3.hashid_hex.substr(0, 8);

        log("INFO", summary);

        res.status = 200;
        res.set_content(summary, "text/plain");
    });

    log("INFO", "Daemon listening on port " + std::to_string(daemon_port) + " (stateless, no identity held)");

    svr.listen("127.0.0.1", daemon_port);

    return 0;
}
#include <asio.hpp>
#include <fstream>
#include <sstream>
#include <vector>
#include <mutex>
#include <thread>
#include <cstring>
#include <string>
#include <algorithm>
#include <cctype>
#include <random>
#include <chrono>
#include "peer.hpp"

#include <sodium.h>
#include <ncurses.h>

using asio::ip::tcp;

std::mutex chat_mutex;
std::vector<std::string> chat_lines;   // formatted display lines, e.g. "abcd1234: hello"

unsigned char g_pk[crypto_box_PUBLICKEYBYTES];
unsigned char g_sk[crypto_box_SECRETKEYBYTES];
unsigned short g_own_port;

// Recipient info, resolved once at startup from the relay's peer list.
unsigned char g_recipient_pk[crypto_box_PUBLICKEYBYTES];
std::string g_recipient_ip;
std::string g_recipient_port;
std::string g_relay_ip;
std::string g_relay_port;
bool g_recipient_found = false;
std::mutex peers_mutex;
std::vector<Peer> g_peers;

// Connects to the relay, sends LIST, parses the count-prefixed response
// into a vector of Peer entries.
std::vector<Peer> fetchPeerList(
    asio::io_context& io,
    const std::string& relay_ip,
    const std::string& relay_port)
{
    std::vector<Peer> peers;

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
        iss >> peer.ip >> peer.port >> peer.pubkey >> peer.hashid >> peer.can_relay;
        peers.push_back(peer);
    }

    return peers;
}

// Builds a full 3-hop onion packet and sends it to a randomly-chosen P1.
// recipient_hashid identifies who the message is ultimately for; the
// relay server's own address (g_relay_ip / g_relay_port, set once at
// startup) is used only to fetch the peer list, never as a message
// destination.
void sendOnionMessage(const std::string& recipient_hashid, const std::string& message) {
    asio::io_context io;
    std::vector<Peer> peers;

    try {
        peers = fetchPeerList(io, g_relay_ip, g_relay_port);
    }
    catch (const std::exception& e) {
        std::lock_guard<std::mutex> lock(chat_mutex);
        chat_lines.push_back(std::string("[route failed] ") + e.what());
        return;
    }

    // Find the recipient's entry.
    Peer recipient_peer;
    bool recipient_found = false;

    for (const auto& p : peers) {
        if (p.hashid == recipient_hashid) {
            recipient_peer = p;
            recipient_found = true;
            break;
        }
    }

    if (!recipient_found) {
        std::lock_guard<std::mutex> lock(chat_mutex);
        chat_lines.push_back("[route failed] recipient not found in peer list");
        return;
    }

    // Filter to relay-capable peers, excluding the recipient itself.
    std::vector<Peer> relay_capable;
    for (const auto& p : peers) {
        if (p.can_relay && p.hashid != recipient_hashid) {
            relay_capable.push_back(p);
        }
    }

    if (relay_capable.size() < 3) {
        std::lock_guard<std::mutex> lock(chat_mutex);
        chat_lines.push_back("[route failed] not enough relay-capable peers (need 3, have "
                              + std::to_string(relay_capable.size()) + ")");
        return;
    }

    // Randomly pick 3 distinct relay-capable peers as P1, P2, P3.
    std::vector<Peer> chosen;
    std::sample(
        relay_capable.begin(), relay_capable.end(),
        std::back_inserter(chosen),
        3,
        std::mt19937{std::random_device{}()}
    );

    Peer& p1_peer = chosen[0];
    Peer& p2_peer = chosen[1];
    Peer& p3_peer = chosen[2];

    // Decode all four public keys we need.
    unsigned char p1_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char p2_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char p3_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char recipient_pk[crypto_box_PUBLICKEYBYTES];
    size_t bin_len;

    bool ok =
        sodium_hex2bin(p1_pk, sizeof(p1_pk), p1_peer.pubkey.c_str(), p1_peer.pubkey.size(), nullptr, &bin_len, nullptr) == 0 &&
        sodium_hex2bin(p2_pk, sizeof(p2_pk), p2_peer.pubkey.c_str(), p2_peer.pubkey.size(), nullptr, &bin_len, nullptr) == 0 &&
        sodium_hex2bin(p3_pk, sizeof(p3_pk), p3_peer.pubkey.c_str(), p3_peer.pubkey.size(), nullptr, &bin_len, nullptr) == 0 &&
        sodium_hex2bin(recipient_pk, sizeof(recipient_pk), recipient_peer.pubkey.c_str(), recipient_peer.pubkey.size(), nullptr, &bin_len, nullptr) == 0;

    if (!ok) {
        std::lock_guard<std::mutex> lock(chat_mutex);
        chat_lines.push_back("[route failed] failed to decode a hop's public key");
        return;
    }

    // Our own hashid, needed as the innermost layer's sender identifier.
    unsigned char own_hash[crypto_generichash_BYTES];
    crypto_generichash(own_hash, sizeof(own_hash), g_pk, sizeof(g_pk), nullptr, 0);

    // Hashes of B, P3, P2 -- needed as the "next hop" field baked into
    // each successive outer layer. P1's hash is never needed since we
    // connect to P1 directly rather than forwarding to it.
    unsigned char hash_b[crypto_generichash_BYTES];
    unsigned char hash_p3[crypto_generichash_BYTES];
    unsigned char hash_p2[crypto_generichash_BYTES];

    crypto_generichash(hash_b, sizeof(hash_b), recipient_pk, sizeof(recipient_pk), nullptr, 0);
    crypto_generichash(hash_p3, sizeof(hash_p3), p3_pk, sizeof(p3_pk), nullptr, 0);
    crypto_generichash(hash_p2, sizeof(hash_p2), p2_pk, sizeof(p2_pk), nullptr, 0);

    // Layer 4 (innermost, for B): hash(A) + message, sealed with B's pubkey.
    std::vector<unsigned char> plaintext_b;
    plaintext_b.push_back(0x01);
    plaintext_b.insert(plaintext_b.end(), own_hash, own_hash + crypto_generichash_BYTES);
    plaintext_b.insert(plaintext_b.end(), message.begin(), message.end());

    std::vector<unsigned char> sealed_b(plaintext_b.size() + crypto_box_SEALBYTES);
    crypto_box_seal(sealed_b.data(), plaintext_b.data(), plaintext_b.size(), recipient_pk);

    // Layer 3 (for P3): hash(B) + sealed_B, sealed with P3's pubkey.
    std::vector<unsigned char> plaintext_p3;
    plaintext_p3.push_back(0x00);
    plaintext_p3.insert(plaintext_p3.end(), hash_b, hash_b + crypto_generichash_BYTES);
    plaintext_p3.insert(plaintext_p3.end(), sealed_b.begin(), sealed_b.end());

    std::vector<unsigned char> sealed_p3(plaintext_p3.size() + crypto_box_SEALBYTES);
    crypto_box_seal(sealed_p3.data(), plaintext_p3.data(), plaintext_p3.size(), p3_pk);

    // Layer 2 (for P2): hash(P3) + sealed_P3, sealed with P2's pubkey.
    std::vector<unsigned char> plaintext_p2;
    plaintext_p2.push_back(0x00);
    plaintext_p2.insert(plaintext_p2.end(), hash_p3, hash_p3 + crypto_generichash_BYTES);
    plaintext_p2.insert(plaintext_p2.end(), sealed_p3.begin(), sealed_p3.end());

    std::vector<unsigned char> sealed_p2(plaintext_p2.size() + crypto_box_SEALBYTES);
    crypto_box_seal(sealed_p2.data(), plaintext_p2.data(), plaintext_p2.size(), p2_pk);

    // Layer 1 (outermost, for P1): hash(P2) + sealed_P2, sealed with P1's pubkey.
    std::vector<unsigned char> plaintext_p1;
    plaintext_p1.push_back(0x00);
    plaintext_p1.insert(plaintext_p1.end(), hash_p2, hash_p2 + crypto_generichash_BYTES);
    plaintext_p1.insert(plaintext_p1.end(), sealed_p2.begin(), sealed_p2.end());

    std::vector<unsigned char> sealed_p1(plaintext_p1.size() + crypto_box_SEALBYTES);
    crypto_box_seal(sealed_p1.data(), plaintext_p1.data(), plaintext_p1.size(), p1_pk);

    // Send 0x02 (onion-hop type) + length prefix + sealed_p1 to P1's address.
    try {
        tcp::resolver resolver(io);
        auto endpoints = resolver.resolve(p1_peer.ip, p1_peer.port);

        tcp::socket socket(io);
        asio::connect(socket, endpoints);

        uint8_t packet_type = 0x02;
        asio::write(socket, asio::buffer(&packet_type, sizeof(packet_type)));

        uint32_t len_net = htonl(static_cast<uint32_t>(sealed_p1.size()));
        asio::write(socket, asio::buffer(&len_net, sizeof(len_net)));
        asio::write(socket, asio::buffer(sealed_p1));
    }
    catch (const std::exception& e) {
        std::lock_guard<std::mutex> lock(chat_mutex);
        chat_lines.push_back(std::string("[send failed] ") + e.what());
        return;
    }

    std::lock_guard<std::mutex> lock(chat_mutex);
    chat_lines.push_back("You (onion via " + p1_peer.hashid.substr(0, 8) + "->"
                          + p2_peer.hashid.substr(0, 8) + "->"
                          + p3_peer.hashid.substr(0, 8) + "): " + message);
}


// Network thread: accepts incoming connections, reads a length-prefixed
// sealed message, decrypts it with our own secret key, and pushes a
// formatted line into chat_lines under the mutex.
void networkThread() {
    asio::io_context io;
    tcp::acceptor acceptor(io, tcp::endpoint(tcp::v4(), g_own_port));

    for (;;) {
        tcp::socket socket(io);
        acceptor.accept(socket);

        std::error_code error;
        uint8_t packet_type;
        asio::read(socket,asio::buffer(&packet_type,sizeof(packet_type)),error);
        if(error) continue;

        if(packet_type==0x01){
            uint32_t len_net;
        asio::read(socket, asio::buffer(&len_net, sizeof(len_net)), error);
        if (error) continue;

        uint32_t len = ntohl(len_net);
        if (len < crypto_box_SEALBYTES) continue;

        std::vector<unsigned char> sealed_blob(len);
        asio::read(socket, asio::buffer(sealed_blob), error);
        if (error) continue;

        std::vector<unsigned char> plaintext(len - crypto_box_SEALBYTES);
        if (plaintext.size() < crypto_generichash_BYTES) continue;

        int ret = crypto_box_seal_open(
            plaintext.data(),
            sealed_blob.data(),
            sealed_blob.size(),
            g_pk,
            g_sk
        );
        if (ret != 0) continue;

        unsigned char sender_hash[crypto_generichash_BYTES];
        std::memcpy(sender_hash, plaintext.data(), crypto_generichash_BYTES);

        std::string message(
            reinterpret_cast<char*>(plaintext.data() + crypto_generichash_BYTES),
            plaintext.size() - crypto_generichash_BYTES
        );

        char sender_hex[crypto_generichash_BYTES * 2 + 1];
        sodium_bin2hex(sender_hex, sizeof(sender_hex), sender_hash, sizeof(sender_hash));

        std::string display = std::string(sender_hex).substr(0, 8) + ": " + message;

        std::lock_guard<std::mutex> lock(chat_mutex);
        chat_lines.push_back(display);

        }else if(packet_type==0x02){
            uint32_t len_net;
            asio::read(socket,asio::buffer(&len_net,sizeof(len_net)),error);
            if(error) continue;

            uint32_t len = ntohl(len_net);
            if(len < crypto_box_SEALBYTES) continue;

            std::vector<unsigned char> sealed_blob(len);
            asio::read(socket,asio::buffer(sealed_blob),error);
            if(error) continue;

            std::vector<unsigned char> layer_plaintext(len-crypto_box_SEALBYTES);

            if(layer_plaintext.size()<1+crypto_generichash_BYTES) continue;

            int ret = crypto_box_seal_open(
                layer_plaintext.data(),
                sealed_blob.data(),
                sealed_blob.size(),
                g_pk,
                g_sk
            );

            if(ret!=0) continue;

            uint8_t layer_type = layer_plaintext[0];

            unsigned char next_hashid_bytes[crypto_generichash_BYTES];
            std::memcpy(next_hashid_bytes,layer_plaintext.data()+1,crypto_generichash_BYTES);

            char next_hashid_hex[crypto_generichash_BYTES*2 + 1];
            sodium_bin2hex(next_hashid_hex,sizeof(next_hashid_hex),next_hashid_bytes,sizeof(next_hashid_bytes));

            std::vector<unsigned char> remaining(
                layer_plaintext.begin() + 1 + crypto_generichash_BYTES,
                layer_plaintext.end()
            );

            if(layer_type == 0x01){
                std::string message(reinterpret_cast<char*>(remaining.data()),remaining.size());
                std::string display = std::string(next_hashid_hex).substr(0,8) + ":" + message;

                std::lock_guard<std::mutex> lock(chat_mutex);
                chat_lines.push_back(display);
            }else if(layer_type==0x00){
                        std::vector<Peer> peers;
        try {
            asio::io_context lookup_io;
            peers = fetchPeerList(lookup_io, g_relay_ip, g_relay_port);
        }
        catch (...) { continue; }

        bool found = false;
        Peer next_peer;
        for (const auto& p : peers) {
            if (p.hashid == std::string(next_hashid_hex)) {
                next_peer = p;
                found = true;
                break;
            }
        }
        if (!found) continue;

        try {
            asio::io_context fwd_io;
            tcp::resolver fwd_resolver(fwd_io);
            auto fwd_endpoints = fwd_resolver.resolve(next_peer.ip, next_peer.port);

            tcp::socket fwd_socket(fwd_io);
            asio::connect(fwd_socket, fwd_endpoints);

            uint8_t fwd_type = 0x02;
            asio::write(fwd_socket, asio::buffer(&fwd_type, sizeof(fwd_type)));

            uint32_t fwd_len_net = htonl(static_cast<uint32_t>(remaining.size()));
            asio::write(fwd_socket, asio::buffer(&fwd_len_net, sizeof(fwd_len_net)));
            asio::write(fwd_socket, asio::buffer(remaining));
        }
        catch (...) { continue; }

            }
        }  
    }
}

void peerRefreshThread() {
    for (;;) {
        std::this_thread::sleep_for(std::chrono::seconds(3));

        try {
            asio::io_context io;
            std::vector<Peer> fresh = fetchPeerList(io, g_relay_ip, g_relay_port);

            std::lock_guard<std::mutex> lock(peers_mutex);
            g_peers = fresh;
        }
        catch (...) {
            // relay temporarily unreachable; just try again next cycle
        }
    }
}
// Sends a plaintext message to the resolved recipient, sealed with their
// public key. Single layer -- no onion routing here, just direct P2P,
// same pattern as peer_a.cpp but using crypto_box_seal instead of
// crypto_box_easy.
void sendMessage(const std::string& message) {
    if (!g_recipient_found) return;

    unsigned char own_hash[crypto_generichash_BYTES];
    crypto_generichash(own_hash, sizeof(own_hash), g_pk, sizeof(g_pk), nullptr, 0);

    std::vector<unsigned char> plaintext;
    plaintext.insert(plaintext.end(), own_hash, own_hash + crypto_generichash_BYTES);
    plaintext.insert(plaintext.end(), message.begin(), message.end());

    std::vector<unsigned char> sealed(plaintext.size() + crypto_box_SEALBYTES);

    crypto_box_seal(sealed.data(), plaintext.data(), plaintext.size(), g_recipient_pk);

    try {
        asio::io_context io;
        tcp::resolver resolver(io);
        auto endpoints = resolver.resolve(g_recipient_ip, g_recipient_port);

        tcp::socket socket(io);
        asio::connect(socket, endpoints);

        uint8_t packet_type = 0x01;
        asio::write(socket,asio::buffer(&packet_type,sizeof(packet_type)));

        uint32_t len_net = htonl(static_cast<uint32_t>(sealed.size()));
        asio::write(socket, asio::buffer(&len_net, sizeof(len_net)));
        asio::write(socket, asio::buffer(sealed));
    }
    catch (const std::exception& e) {
        std::lock_guard<std::mutex> lock(chat_mutex);
        chat_lines.push_back(std::string("[send failed] ") + e.what());
        return;
    }

    std::lock_guard<std::mutex> lock(chat_mutex);
    chat_lines.push_back("You: " + message);
}

int main(int argc, char* argv[]) {
    if (argc != 6) {
        std::cerr
            << "Usage: " << argv[0]
            << " <relay_ip> <relay_port> <own_port> <recipient_hashid> <can_relay 0|1>\n";
        return 1;
    }

    std::string relay_ip = argv[1];
    std::string relay_port = argv[2];
    g_own_port = static_cast<unsigned short>(std::stoi(argv[3]));
    std::string recipient_hashid = argv[4];
    g_relay_ip = relay_ip;
    g_relay_port = relay_port;
    bool can_relay_flag = (std::string(argv[5]) == "1");

    if (sodium_init() < 0) return 1;

    // Load or generate our own keypair
    std::ifstream keyfile_in("client.key", std::ios::binary);

    if (keyfile_in) {
        keyfile_in.read(reinterpret_cast<char*>(g_pk), sizeof(g_pk));
        keyfile_in.read(reinterpret_cast<char*>(g_sk), sizeof(g_sk));
    }
    else {
        crypto_box_keypair(g_pk, g_sk);

        std::ofstream keyfile_out("client.key", std::ios::binary);
        keyfile_out.write(reinterpret_cast<char*>(g_pk), sizeof(g_pk));
        keyfile_out.write(reinterpret_cast<char*>(g_sk), sizeof(g_sk));
    }

    char pk_hex[crypto_box_PUBLICKEYBYTES * 2 + 1];
    sodium_bin2hex(pk_hex, sizeof(pk_hex), g_pk, sizeof(g_pk));

    unsigned char hash[crypto_generichash_BYTES];
    crypto_generichash(hash, sizeof(hash), g_pk, sizeof(g_pk), nullptr, 0);

    char hash_hex[crypto_generichash_BYTES * 2 + 1];
    sodium_bin2hex(hash_hex, sizeof(hash_hex), hash, sizeof(hash));

    // Fetch peer list BEFORE starting ncurses, so a relay-down error is
    // readable instead of garbled inside curses mode.
    std::vector<Peer> peers;
    try {
        asio::io_context io;
        g_peers = fetchPeerList(io, relay_ip, relay_port);
    }
    catch (const std::exception& e) {
        std::cerr << "Failed to fetch peer list: " << e.what() << "\n";
        return 1;
    }

    // Resolve the recipient from the fetched list.
    for (const auto& p : g_peers) {
        if (p.hashid == recipient_hashid) {
            g_recipient_ip = p.ip;
            g_recipient_port = p.port;

            size_t bin_len;
            int r = sodium_hex2bin(
                g_recipient_pk, sizeof(g_recipient_pk),
                p.pubkey.c_str(), p.pubkey.size(),
                nullptr, &bin_len, nullptr
            );

            if (r == 0) g_recipient_found = true;
            break;
        }
    }

    // Register ourselves with the relay so others (including the
    // recipient) can look us up and reply.
    try {
        asio::io_context io;
        tcp::resolver resolver(io);
        auto endpoints = resolver.resolve(relay_ip, relay_port);

        tcp::socket socket(io);
        asio::connect(socket, endpoints);

        std::string command =
            "REGISTER 127.0.0.1 " + std::to_string(g_own_port) +
            " " + std::string(pk_hex) +
            " " + std::string(hash_hex) + 
            " " + (can_relay_flag ? "1" : "0") + "\n";

        asio::write(socket, asio::buffer(command));

        asio::streambuf reg_buf;
        std::error_code reg_error;
        asio::read_until(socket, reg_buf, '\n', reg_error);
        // response intentionally ignored here; registration failure is
        // non-fatal for this test build, network thread will still work
        // for anyone who already has our address hardcoded/looked-up.
    }
    catch (...) {
        // registration failure is non-fatal for this test build
    }

    // Start the network thread (listens for incoming messages)
    std::thread net_thread(networkThread);
    net_thread.detach();
    std::thread refresh_thread(peerRefreshThread);
    refresh_thread.detach();

    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(1);
    timeout(100);
    refresh();

    int term_h, term_w;
    getmaxyx(stdscr, term_h, term_w);

    int header_h = 2;

    int right_w = term_w * 30 / 100;
    int left_w = term_w - right_w;

    int peer_h = (term_h - header_h) * 20 / 100;
    int chat_h = (term_h - header_h) - peer_h;

    int relay_h = chat_h * 60 / 100;
    int help_h = chat_h - relay_h;

    mvprintw(0, 1, "Your hash id: %s", hash_hex);
    mvprintw(1, 1, "Chatting with: %s", recipient_hashid.substr(0, 16).c_str());

    WINDOW* chat_win  = newwin(chat_h, left_w, header_h, 0);
    WINDOW* peer_win  = newwin(peer_h, left_w, header_h + chat_h, 0);
    WINDOW* relay_win = newwin(relay_h, right_w, header_h, left_w);
    WINDOW* help_win  = newwin(help_h, right_w, header_h + relay_h, left_w);

    box(peer_win, 0, 0);
    box(relay_win, 0, 0);
    box(help_win, 0, 0);

    mvwprintw(peer_win, 0, 2, " Peer List ");
    mvwprintw(relay_win, 0, 2, " Relay Server Info ");
    mvwprintw(help_win, 0, 2, " Help ");

    mvwprintw(relay_win, 2, 2, "IP   %s", relay_ip.c_str());
    mvwprintw(relay_win, 3, 2, "Port %s", relay_port.c_str());

    mvwprintw(help_win, 2, 2, "Enter - send message");
    mvwprintw(help_win, 3, 2, "Ctrl+C - quit");

    

    std::string input_buffer;

    for (;;) {
        werase(chat_win);
        box(chat_win, 0, 0);
        mvwprintw(chat_win, 0, 2, " Chat ");

        werase(peer_win);
        box(peer_win,0,0);
        mvwprintw(peer_win,0,2,"Peer List");

        {
            std::lock_guard<std::mutex> lock(peers_mutex);

            int peer_inner_h = peer_h - 2;
            int peer_inner_w = left_w - 4;

            for (size_t i = 0; i < g_peers.size() && (int)i < peer_inner_h - 1; i++) {
                std::string display = g_peers[i].hashid;
                if ((int)display.size() > peer_inner_w)
                    display = display.substr(0, peer_inner_w);
                mvwprintw(peer_win, 2 + (int)i, 2, "%s", display.c_str());
            }
        }
        {
            std::lock_guard<std::mutex> lock(chat_mutex);
            int max_lines = getmaxy(chat_win) - 3;
            int start = std::max(0, (int)chat_lines.size() - max_lines);

            int row = 1;
            for (int i = start; i < (int)chat_lines.size(); i++) {
                mvwprintw(chat_win, row++, 2, "%s", chat_lines[i].c_str());
            }
        }

        mvwprintw(chat_win, getmaxy(chat_win) - 2, 2, "> %s", input_buffer.c_str());
        wmove(chat_win, getmaxy(chat_win) - 2, (int)input_buffer.size() + 4);

        wnoutrefresh(stdscr);
        wnoutrefresh(chat_win);
        wnoutrefresh(peer_win);
        wnoutrefresh(relay_win);
        wnoutrefresh(help_win);
        doupdate();

        int ch = getch();

        if (ch == ERR) {
            continue;
        }
        else if (ch == '\n') {
            if (!input_buffer.empty()) {
                sendOnionMessage(recipient_hashid,input_buffer);
                input_buffer.clear();
            }
        }
        else if (ch == KEY_BACKSPACE || ch == 127) {
            if (!input_buffer.empty()) input_buffer.pop_back();
        }
        else if (isprint(ch)) {
            input_buffer += (char)ch;
        }else if(ch==24){
            break;
        }
    }

    endwin();
    return 0;
}

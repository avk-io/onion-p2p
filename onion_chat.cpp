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
bool g_recipient_found = false;

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
        iss >> peer.ip >> peer.port >> peer.pubkey >> peer.hashid;
        peers.push_back(peer);
    }

    return peers;
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
    if (argc != 5) {
        std::cerr
            << "Usage: " << argv[0]
            << " <relay_ip> <relay_port> <own_port> <recipient_hashid>\n";
        return 1;
    }

    std::string relay_ip = argv[1];
    std::string relay_port = argv[2];
    g_own_port = static_cast<unsigned short>(std::stoi(argv[3]));
    std::string recipient_hashid = argv[4];

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
        peers = fetchPeerList(io, relay_ip, relay_port);
    }
    catch (const std::exception& e) {
        std::cerr << "Failed to fetch peer list: " << e.what() << "\n";
        return 1;
    }

    // Resolve the recipient from the fetched list.
    for (const auto& p : peers) {
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
            " " + std::string(hash_hex) + "\n";

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

    int peer_inner_h = peer_h - 2;
    int peer_inner_w = left_w - 4;

    for (size_t i = 0; i < peers.size() && (int)i < peer_inner_h - 1; i++) {
        std::string display = peers[i].hashid;
        if ((int)display.size() > peer_inner_w)
            display = display.substr(0, peer_inner_w);
        mvwprintw(peer_win, 2 + (int)i, 2, "%s", display.c_str());
    }

    std::string input_buffer;

    for (;;) {
        werase(chat_win);
        box(chat_win, 0, 0);
        mvwprintw(chat_win, 0, 2, " Chat ");

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
                sendMessage(input_buffer);
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
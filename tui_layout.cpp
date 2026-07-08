#include <asio.hpp>
#include <sodium.h>
#include <fstream>
#include <sstream>
#include <vector>
#include <cstring>
#include <string>
#include "peer.hpp"
#include <ncurses.h>

using asio::ip::tcp;

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

int main(int argc, char* argv[]) {
    std::string relay_ip = (argc > 1) ? argv[1] : "127.0.0.1";
    std::string relay_port = (argc > 2) ? argv[2] : "12345";

    if (sodium_init() < 0) return 1;

    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    unsigned char sk[crypto_box_SECRETKEYBYTES];

    std::ifstream keyfile_in("tui.key", std::ios::binary);
    if (keyfile_in) {
        keyfile_in.read(reinterpret_cast<char*>(pk), sizeof(pk));
        keyfile_in.read(reinterpret_cast<char*>(sk), sizeof(sk));
    } else {
        crypto_box_keypair(pk, sk);
        std::ofstream keyfile_out("tui.key", std::ios::binary);
        keyfile_out.write(reinterpret_cast<char*>(pk), sizeof(pk));
        keyfile_out.write(reinterpret_cast<char*>(sk), sizeof(sk));
    }

    unsigned char hash[crypto_generichash_BYTES];
    crypto_generichash(hash, sizeof(hash), pk, sizeof(pk), nullptr, 0);

    char hash_hex[crypto_generichash_BYTES * 2 + 1];
    sodium_bin2hex(hash_hex, sizeof(hash_hex), hash, sizeof(hash));

    // Fetch peer list BEFORE entering ncurses mode, so any exception
    // (relay down, etc.) prints a normal error message instead of getting
    // swallowed/garbled inside a curses screen.
    asio::io_context io;
    std::vector<Peer> peers;

    try {
        peers = fetchPeerList(io, relay_ip, relay_port);
    }
    catch (const std::exception& e) {
        std::cerr << "Failed to fetch peer list: " << e.what() << "\n";
        return 1;
    }

    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);
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

    WINDOW* chat_win  = newwin(chat_h, left_w, header_h, 0);
    WINDOW* peer_win  = newwin(peer_h, left_w, header_h + chat_h, 0);

    WINDOW* relay_win = newwin(relay_h, right_w, header_h, left_w);
    WINDOW* help_win  = newwin(help_h, right_w, header_h + relay_h, left_w);

    box(chat_win, 0, 0);
    box(peer_win, 0, 0);
    box(relay_win, 0, 0);
    box(help_win, 0, 0);

    mvwprintw(chat_win, 0, 2, " Chat ");
    mvwprintw(peer_win, 0, 2, " Peer List ");
    mvwprintw(relay_win, 0, 2, " Relay Server Info ");
    mvwprintw(help_win, 0, 2, " Help ");

    mvwprintw(relay_win, 2, 2, "IP   %s", relay_ip.c_str());
    mvwprintw(relay_win, 3, 2, "Port %s", relay_port.c_str());

    // Peer list content -- one hashid per line, truncated to fit the window
    int peer_inner_h = peer_h - 2;   // rows available inside the border
    int peer_inner_w = left_w - 4;   // cols available inside the border

    for (size_t i = 0; i < peers.size() && (int)i < peer_inner_h - 1; i++) {
        std::string display = peers[i].hashid;
        if ((int)display.size() > peer_inner_w)
            display = display.substr(0, peer_inner_w);

        mvwprintw(peer_win, 2 + (int)i, 2, "%s", display.c_str());
    }

    wnoutrefresh(stdscr);
    wnoutrefresh(chat_win);
    wnoutrefresh(peer_win);
    wnoutrefresh(relay_win);
    wnoutrefresh(help_win);
    doupdate();

    getch();

    delwin(chat_win);
    delwin(peer_win);
    delwin(relay_win);
    delwin(help_win);

    endwin();
    return 0;
}
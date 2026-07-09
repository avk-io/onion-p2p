#include <bits/stdc++.h>
#include <asio.hpp>
#include "peer.hpp"

using asio::ip::tcp;

std::mutex peers_mutex;   

std::string handleCommand(const std::string& line,
                          std::vector<Peer>& peers)
{
    std::istringstream iss(line);

    std::string command;
    iss >> command;

    if (command == "REGISTER") {
        Peer peer;

        if (!(iss >> peer.ip >> peer.port >> peer.pubkey >> peer.hashid >> peer.can_relay))
            return "ERROR Invalid REGISTER command\n";

        peers.push_back(peer);
        return "OK Registered\n";
    }

    if (command == "LIST") {
        std::ostringstream out;
        out << peers.size() << "\n";

        for (const auto& peer : peers) {
            out << peer.ip << " "
                << peer.port << " "
                << peer.pubkey << " "
                << peer.hashid << " "
                << peer.can_relay << "\n";
        }

        return out.str();
    }

    return "ERROR Unknown command\n";
}

void handleClient(tcp::socket socket, std::vector<Peer>& peers) {
    for (;;) {
        asio::streambuf buf;
        std::error_code error;

        asio::read_until(socket, buf, '\n', error);

        if (error == asio::error::eof)
            break;
        else if (error) {
            std::cerr << "Error: " << error.message() << "\n";
            break;
        }

        std::istream is(&buf);
        std::string line;
        std::getline(is, line);
        std::cout << "Received: " << line << "\n";

        std::string response;
        {
            std::lock_guard<std::mutex> lock(peers_mutex);
            response = handleCommand(line, peers);
            
        }
        std::cout << "Response: " << response;

        asio::write(socket, asio::buffer(response));
    }
    std::cout << "Client disconnected\n";
}

int main() {
    try {
        asio::io_context io;
        tcp::acceptor acceptor(io,
                               tcp::endpoint(tcp::v4(), 12345));

        std::vector<Peer> peers;

            for (;;) {
                tcp::socket socket(io);
                acceptor.accept(socket);
                std::cout<<"Client connected\n";

                std::thread(
                    handleClient,
                    std::move(socket), 
                    std::ref(peers)
                ).detach();
            }
    }
    catch (std::exception& e) {
        std::cerr << "Exception: "
                  << e.what() << '\n';
    }

    return 0;
}
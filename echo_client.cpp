#include <bits/stdc++.h>
#include <asio.hpp>

using asio::ip::tcp;

int main() {
    try {
        asio::io_context io;

        tcp::resolver resolver(io);

        tcp::resolver::results_type endpoints =
            resolver.resolve("127.0.0.1", "12345");

        tcp::socket socket(io);
        asio::connect(socket, endpoints);

        for (;;) {
            std::string s;
            std::getline(std::cin, s);

            if (s == "quit")
                break;

            s+='\n';
            asio::write(socket, asio::buffer(s+'\n'));

            std::array<char, 128> buf;
            std::error_code error;

            size_t len = socket.read_some(asio::buffer(buf), error);

            if (error == asio::error::eof)
                break;
            else if (error)
                throw std::system_error(error);

            std::cout.write(buf.data(), len);
            std::cout << '\n';
        }
    }
    catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << '\n';
    }

    return 0;
}
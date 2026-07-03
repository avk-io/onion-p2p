#include<bits/stdc++.h>
#include<asio.hpp>
using asio::ip::tcp;

int main(){
    try{
        asio::io_context io;

        tcp::acceptor acceptor(io,tcp::endpoint(tcp::v4(),12345));

        for(;;){
            tcp::socket socket(io);
            acceptor.accept(socket);

            for(;;){
                std::array<char,128> buf;
                std::error_code error;

                size_t len = socket.read_some(asio::buffer(buf),error);

                if(error==asio::error::eof)
                    break;
                else if(error){
                    throw std::system_error(error);
                }
                std::cout.write(buf.data(),len);
                std::cout<<std::flush;
                std::cout<<"\n";
                asio::write(socket,asio::buffer(buf.data(),len));
            }
            std::cout<<"\nClient disconnected\n";
        }
    }catch(std::exception& e){
        std::cerr<<"Exception: "<<e.what()<<"\n";
    }
}

#include<bits/stdc++.h>
#include<asio.hpp>
#include <sodium.h>
#include <arpa/inet.h>
#include <fstream>
using asio::ip::tcp;

int main(){
    try{
        if(sodium_init()<0){
            std::cerr<<"libsodium init failed\n";
            return 1;
        }

        unsigned char b_pk[crypto_box_PUBLICKEYBYTES];
        unsigned char b_sk[crypto_box_SECRETKEYBYTES];
        
        std::ifstream keyfile_in("b.key", std::ios::binary);
        if (keyfile_in) {
            keyfile_in.read(reinterpret_cast<char*>(b_pk), sizeof(b_pk));
            keyfile_in.read(reinterpret_cast<char*>(b_sk), sizeof(b_sk));
        } else {
            crypto_box_keypair(b_pk, b_sk);
            std::ofstream keyfile_out("b.key", std::ios::binary);
            keyfile_out.write(reinterpret_cast<char*>(b_pk), sizeof(b_pk));
            keyfile_out.write(reinterpret_cast<char*>(b_sk), sizeof(b_sk));
        }

        char b_pk_hex[crypto_box_PUBLICKEYBYTES*2 + 1];
        sodium_bin2hex(
            b_pk_hex,
            sizeof(b_pk_hex),
            b_pk,
            sizeof(b_pk)
        );

        std::cout << "B Public Key:\n"
                  << b_pk_hex << "\n";

        const char* A_PUBKEY_HEX = "7ce5ac9b9221adef402cabd4f2b25b85367ef418964b0886ecf90de07f84f044";

        asio::io_context io;

        tcp::acceptor acceptor(io,tcp::endpoint(tcp::v4(),7000));

        for(;;){
            tcp::socket socket(io);
            acceptor.accept(socket);
            std::cout<<"Client connected\n";

            for(;;){
                unsigned char nonce[crypto_box_NONCEBYTES];
                std::error_code error;
                asio::read(socket,asio::buffer(nonce,crypto_box_NONCEBYTES),error);
                if(error == asio::error::eof) break;
                else if(error) {
                    std::cerr << "Read error: " << error.message()<<"\n";
                    break;
                }

                uint32_t len_net;
                asio::read(socket,asio::buffer(&len_net,sizeof(len_net)),error);
                if(error) break;

                uint32_t len = ntohl(len_net);

                if(len<crypto_box_MACBYTES){
                    std::cerr<<"Invalid ciphertext length\n";
                    continue;
                }

                std::vector<unsigned char> ciphertext(len);
                asio::read(socket,asio::buffer(ciphertext),error);
                if(error) break;

                unsigned char a_pk[crypto_box_PUBLICKEYBYTES];
                size_t bin_len;

                int r = sodium_hex2bin(
                    a_pk,
                    sizeof(a_pk),
                    A_PUBKEY_HEX,
                    strlen(A_PUBKEY_HEX),
                    nullptr,
                    &bin_len,
                    nullptr
                );

                if(r!=0){
                    std::cerr << "Invalid A public key\n";
                    return 1;
                }

                std::vector<unsigned char> plaintext(
                    len - crypto_box_MACBYTES
                );

                int ret = crypto_box_open_easy(
                    plaintext.data(),
                    ciphertext.data(),
                    len,
                    nonce,
                    a_pk,
                    b_sk
                );

                if(ret!=0){
                    std::cerr<<"Decryption failed:Message forged or keys incorrect\n";
                    continue;
                }

                std::cout.write(reinterpret_cast<char*>(plaintext.data()),plaintext.size());
                std::cout << "\n";
                }
            std::cout<<"Client disconnected\n";
        }
    }catch(std::exception& e){
        std::cerr<<"Exception: "<<e.what()<<"\n";
    }
}

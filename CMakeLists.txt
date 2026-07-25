cmake_minimum_required(VERSION 3.20)

project(EchoServer)

set(CMAKE_CXX_STANDARD 20)

add_executable(echo_server echo_server.cpp)
target_include_directories(echo_server PRIVATE /home/caliz/chatNT/asio/include)
target_compile_definitions(echo_server PRIVATE ASIO_STANDALONE)
target_link_libraries(echo_server PRIVATE pthread)

add_executable(echo_client echo_client.cpp)
target_include_directories(echo_client PRIVATE /home/caliz/chatNT/asio/include)
target_compile_definitions(echo_client PRIVATE ASIO_STANDALONE)
target_link_libraries(echo_client PRIVATE pthread)

add_executable(relay_server relay_server.cpp)
target_include_directories(relay_server PRIVATE /home/caliz/chatNT/asio/include)
target_compile_definitions(relay_server PRIVATE ASIO_STANDALONE)
target_link_libraries(relay_server PRIVATE pthread)

add_executable(keygen_test keygen_test.cpp)
target_link_libraries(keygen_test PRIVATE sodium)

add_executable(peer_client peer_client.cpp)
target_include_directories(peer_client PRIVATE /home/caliz/chatNT/asio/include)
target_compile_definitions(peer_client PRIVATE ASIO_STANDALONE)
target_link_libraries(peer_client PRIVATE sodium pthread)

add_executable(crypto_test crypto_test.cpp)
target_link_libraries(crypto_test PRIVATE sodium)

add_executable(peer_b peer_b.cpp)
target_include_directories(peer_b PRIVATE /home/caliz/chatNT/asio/include)
target_compile_definitions(peer_b PRIVATE ASIO_STANDALONE)
target_link_libraries(peer_b PRIVATE pthread sodium)

add_executable(peer_a peer_a.cpp)
target_include_directories(peer_a PRIVATE /home/caliz/chatNT/asio/include)
target_compile_definitions(peer_a PRIVATE ASIO_STANDALONE)
target_link_libraries(peer_a PRIVATE pthread sodium)

add_executable(onion_test onion_test.cpp)
target_link_libraries(onion_test PRIVATE sodium)

add_executable(onion_b onion_b.cpp)
target_include_directories(onion_b PRIVATE /home/caliz/chatNT/asio/include)
target_compile_definitions(onion_b PRIVATE ASIO_STANDALONE)
target_link_libraries(onion_b PRIVATE pthread sodium)



add_executable(onion_a onion_a.cpp)
target_include_directories(onion_a PRIVATE /home/caliz/chatNT/asio/include)
target_compile_definitions(onion_a PRIVATE ASIO_STANDALONE)
target_link_libraries(onion_a PRIVATE pthread sodium)

add_executable(onion_relay onion_relay.cpp)
target_include_directories(onion_relay PRIVATE /home/caliz/chatNT/asio/include)
target_compile_definitions(onion_relay PRIVATE ASIO_STANDALONE)
target_link_libraries(onion_relay PRIVATE pthread sodium)

add_executable(tui_test tui_test.cpp)
target_link_libraries(tui_test PRIVATE ncurses)

add_executable(tui_layout tui_layout.cpp)
target_include_directories(tui_layout PRIVATE /home/caliz/chatNT/asio/include)
target_compile_definitions(tui_layout PRIVATE ASIO_STANDALONE)
target_link_libraries(tui_layout PRIVATE ncurses sodium pthread)

add_executable(onion_chat onion_chat.cpp)
target_include_directories(onion_chat PRIVATE /home/caliz/chatNT/asio/include)
target_compile_definitions(onion_chat PRIVATE ASIO_STANDALONE)
target_link_libraries(onion_chat PRIVATE ncurses sodium pthread)

add_executable(daemon_test daemon_test.cpp)
target_include_directories(daemon_test PRIVATE ${CMAKE_SOURCE_DIR}/vendor)
target_link_libraries(daemon_test PRIVATE pthread)

add_executable(relay_http relay_http.cpp)
target_include_directories(relay_http PRIVATE ${CMAKE_SOURCE_DIR}/vendor)
target_link_libraries(relay_http PRIVATE pthread sodium)

add_executable(make_test_packet make_test_packet.cpp)
target_link_libraries(make_test_packet PRIVATE sodium)

add_executable(make_test_packet2 make_test_packet2.cpp)
target_link_libraries(make_test_packet2 PRIVATE sodium)

add_executable(daemon daemon.cpp)
target_include_directories(daemon PRIVATE ${CMAKE_SOURCE_DIR}/vendor)
target_link_libraries(daemon PRIVATE pthread sodium)

target_link_libraries(relay_http PRIVATE pthread sodium sqlite3)

find_package(OpenSSL REQUIRED)

target_compile_definitions(relay_http PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)
target_link_libraries(relay_http PRIVATE pthread sodium sqlite3 OpenSSL::SSL OpenSSL::Crypto)

find_package(OpenSSL REQUIRED)

target_compile_definitions(daemon PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)
target_link_libraries(daemon PRIVATE pthread sodium sqlite3 OpenSSL::SSL OpenSSL::Crypto)

add_executable(cross_test cross_test.cpp)
target_link_libraries(cross_test PRIVATE sodium)

add_executable(tor_test tor_test.cpp)
target_link_libraries(tor_test PRIVATE curl)
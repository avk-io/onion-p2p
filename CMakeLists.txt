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
#include <bits/stdc++.h>
#include <sodium.h>

int main(){
    if(sodium_init()<0) return 1;

    unsigned char a_pk[crypto_box_PUBLICKEYBYTES],a_sk[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(a_pk,a_sk);

    unsigned char b_pk[crypto_box_PUBLICKEYBYTES], b_sk[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(b_pk, b_sk);

    std::string message = "Hello B , this is A";

    unsigned char nonce[crypto_box_NONCEBYTES];
    randombytes_buf(nonce,sizeof(nonce));

    std::vector<unsigned char> ciphertext(
        message.size() + crypto_box_MACBYTES
    );

    if(crypto_box_easy(
        ciphertext.data(),
        reinterpret_cast<const unsigned char*>(message.data()),
        message.size(),
        nonce,
        b_pk,
        a_sk
    )!=0)
    {
        std::cerr<<"Encryption failes\n";
        return 1;
    }

    std::vector<unsigned char> decrypted(message.size());

     if (crypto_box_open_easy(
            decrypted.data(),
            ciphertext.data(),
            ciphertext.size(),
            nonce,
            a_pk,
            b_sk
        ) != 0)
    {
        std::cerr << "Decryption failed\n";
        return 1;
    }

    std::string recovered(
        reinterpret_cast<char*>(decrypted.data()),
        decrypted.size()
    );

    std::cout << "Original : " << message << '\n';
    std::cout << "Recovered: " << recovered << '\n';

    if (message == recovered)
        std::cout << "SUCCESS: Messages match\n";
    else
        std::cout << "FAILURE: Messages differ\n";

    // after your successful round-trip test, add:
ciphertext[0] ^= 0xFF;  // corrupt one byte

std::vector<unsigned char> tampered_decrypted(message.size());
int tamper_result = crypto_box_open_easy(
    tampered_decrypted.data(),
    ciphertext.data(),
    ciphertext.size(),
    nonce,
    a_pk,
    b_sk
);

std::cout << "Tamper test: " << (tamper_result != 0 ? "PASS (correctly rejected)" : "FAIL (accepted tampered data!)") << '\n';

    return 0;

}
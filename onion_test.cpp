#include <bits/stdc++.h>
#include <sodium.h>

using int64 = long long;

int main(){
    if(sodium_init()<0) return 1;

    unsigned char A_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char A_sk[crypto_box_SECRETKEYBYTES];

    unsigned char P1_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char P1_sk[crypto_box_SECRETKEYBYTES];

    unsigned char B_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char B_sk[crypto_box_SECRETKEYBYTES];

    crypto_box_keypair(A_pk,A_sk);
    crypto_box_keypair(P1_pk,P1_sk);
    crypto_box_keypair(B_pk,B_sk);

    unsigned char hash_A[crypto_generichash_BYTES];
    crypto_generichash(hash_A,sizeof hash_A,A_pk,sizeof A_pk,nullptr,0);

    unsigned char hash_B[crypto_generichash_BYTES];
    crypto_generichash(hash_B,sizeof hash_B,B_pk,sizeof B_pk,nullptr,0);

    std::string message = "Hi B, this is A, via P1";

    std::vector<unsigned char> plaintext_B;

    plaintext_B.insert(
        plaintext_B.end(),
        hash_A,
        hash_A + crypto_generichash_BYTES
    );
    plaintext_B.insert(
        plaintext_B.end(),
        message.begin(),
        message.end()
    );

    std::vector<unsigned char> sealed_B(
        plaintext_B.size() + crypto_box_SEALBYTES
    );

    crypto_box_seal(
        sealed_B.data(),
        plaintext_B.data(),
        plaintext_B.size(),
        B_pk
    );

    std::vector<unsigned char> plaintext_P1;

    plaintext_P1.insert(
        plaintext_P1.end(),
        hash_B,
        hash_B + crypto_generichash_BYTES
    );

    plaintext_P1.insert(
        plaintext_P1.end(),
        sealed_B.begin(),
        sealed_B.end()
    );

    std::vector<unsigned char> sealed_P1(
        plaintext_P1.size() + crypto_box_SEALBYTES
    );

    crypto_box_seal(
        sealed_P1.data(),
        plaintext_P1.data(),
        plaintext_P1.size(),
        P1_pk
    );

    std::vector<unsigned char> layer_plaintext(
        sealed_P1.size() - crypto_box_SEALBYTES
    );

     int ret = crypto_box_seal_open(
        layer_plaintext.data(),
        sealed_P1.data(),
        sealed_P1.size(),
        P1_pk,
        P1_sk
    );

    if(ret!=0){
        std::cerr<<"Decryption failed\n";
        return 1;
    }

    std::vector<unsigned char> next_hashid(
        layer_plaintext.begin(),
        layer_plaintext.begin() + crypto_generichash_BYTES
    );

    std::vector<unsigned char> remaining_blob(
        layer_plaintext.begin() + crypto_generichash_BYTES,
        layer_plaintext.end()
    );

    char next_hash_hex[crypto_generichash_BYTES*2 + 1];

    sodium_bin2hex(
        next_hash_hex,
        sizeof(next_hash_hex),
        next_hashid.data(),
        next_hashid.size()
    );

    std::cout<<next_hash_hex<<"\n";

    if(remaining_blob==sealed_B){
        std::cout<<"remaining_blob matches sealed_B\n";
    }else{
        std::cout<<"Mismatch occured\n";
    }

    if (next_hashid == std::vector<unsigned char>(hash_B, hash_B + crypto_generichash_BYTES))
        std::cout << "next_hashid correctly matches hash(B)\n";
    else
        std::cout << "MISMATCH: next_hashid does not match hash(B)\n";

    std::vector<unsigned char> b_plaintext(
        remaining_blob.size() - crypto_box_SEALBYTES
    );

     ret = crypto_box_seal_open(
        b_plaintext.data(),
        remaining_blob.data(),
        remaining_blob.size(),
        B_pk,
        B_sk
    );

    if(ret!=0){
        std::cerr<<"B failed to decrypt\n";
        return 1;
    }

    std::vector<unsigned char> sender_hashid(
        b_plaintext.begin(),
        b_plaintext.begin() + crypto_generichash_BYTES
    );

    std::vector<unsigned char> recovered_message(
        b_plaintext.begin() + crypto_generichash_BYTES,
        b_plaintext.end()
    );

    std::string recovered(
        recovered_message.begin(),
        recovered_message.end()
    );

    std::cout<<"Recovered message: "
             << recovered << "\n";

    char sender_hash_hex[crypto_generichash_BYTES*2 + 1];

    sodium_bin2hex(
        sender_hash_hex,
        sizeof(sender_hash_hex),
        sender_hashid.data(),
        sender_hashid.size()
    );
    std::cout<<"Sender hashid: "
             << sender_hash_hex << "\n";

    if (sender_hashid == std::vector<unsigned char>(hash_A, hash_A + crypto_generichash_BYTES))
        std::cout << "sender_hashid correctly matches hash(A)\n";
    else
        std::cout << "MISMATCH: sender_hashid does not match hash(A)\n";

}       
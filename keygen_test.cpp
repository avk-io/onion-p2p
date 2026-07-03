#include <bits/stdc++.h>
#include <sodium.h>

using int64 = long long;

bool verifyHashId(const unsigned char pk[crypto_box_PUBLICKEYBYTES],
                  const unsigned char claimed_hash[crypto_generichash_BYTES])
{
    unsigned char computed_hash[crypto_generichash_BYTES];
    crypto_generichash(
        computed_hash,
        sizeof computed_hash,
        pk,
        crypto_box_PUBLICKEYBYTES,
        nullptr,
        0
    );
    return sodium_memcmp(
        computed_hash,
        claimed_hash,
        crypto_generichash_BYTES
    ) == 0;

}

int main(){
    if(sodium_init()<0){
        std::cerr<<"libsodium init failed\n";
        return 1;
    }

    unsigned char pk[crypto_box_PUBLICKEYBYTES]; 
    unsigned char sk[crypto_box_SECRETKEYBYTES];

    crypto_box_keypair(pk,sk);

    unsigned char hash[crypto_generichash_BYTES];
    crypto_generichash(hash,sizeof hash,pk,sizeof pk,NULL,0);

    char pk_hex[crypto_box_PUBLICKEYBYTES*2 + 1];
    char hash_hex[crypto_generichash_BYTES*2 + 1];

    bool valid = verifyHashId(pk, hash);
    std::cout << "Valid hash check: " << (valid ? "PASS" : "FAIL") << '\n';

    unsigned char bad_hash[crypto_generichash_BYTES];
    memcpy(bad_hash, hash, sizeof(hash));
    bad_hash[0] ^= 0xFF;   // corrupt one byte

    bool invalid = verifyHashId(pk, bad_hash);
    std::cout << "Corrupted hash check: " << (invalid ? "FAIL (should have been rejected!)" : "PASS (correctly rejected)") << '\n';

    sodium_bin2hex(
        pk_hex,
        sizeof(pk_hex),
        pk,
        sizeof(pk)
    );

    sodium_bin2hex(
        hash_hex,
        sizeof(hash_hex),
        hash,
        sizeof(hash)
    );

    std::cout<<"Public Key : "<< pk_hex << '\n';
    std::cout<<"Hash Id : "<<hash_hex<<'\n';

    return 0;
}
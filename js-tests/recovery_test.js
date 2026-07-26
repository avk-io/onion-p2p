import * as bip39 from 'bip39';
import sodium from 'libsodium-wrappers';

async function testRecoveryPhrase() {
    await sodium.ready;

    // 1. Generate a recovery phrase (this internally generates the
    //    random entropy and encodes it as words)
    const mnemonic = bip39.generateMnemonic(256);   // 256 bits -> 24 words
    console.log('Recovery phrase:', mnemonic);

    // 2. Convert the mnemonic back into raw entropy bytes
    const entropyHex = bip39.mnemonicToEntropy(mnemonic);
    const seed = sodium.from_hex(entropyHex);
    console.log('Seed (hex):', entropyHex, '- length:', seed.length, 'bytes');

    // 3. Deterministically generate a keypair from that seed
    const keypair = sodium.crypto_box_seed_keypair(seed);
    console.log('Public key (hex):', sodium.to_hex(keypair.publicKey));
    console.log('Private key (hex):', sodium.to_hex(keypair.privateKey));

    // 4. Prove determinism: regenerate from the SAME mnemonic, confirm
    //    identical keys come out -- this is the actual "recovery" test
    const entropyHex2 = bip39.mnemonicToEntropy(mnemonic);
    const seed2 = sodium.from_hex(entropyHex2);
    const keypair2 = sodium.crypto_box_seed_keypair(seed2);

    console.log('Recovered public key matches:', 
        sodium.to_hex(keypair.publicKey) === sodium.to_hex(keypair2.publicKey));
    console.log('Recovered private key matches:', 
        sodium.to_hex(keypair.privateKey) === sodium.to_hex(keypair2.privateKey));
}

testRecoveryPhrase();
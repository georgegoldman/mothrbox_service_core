use aes_gcm::{
    aead::{rand_core::RngCore, Aead, KeyInit, OsRng}, Aes256Gcm, Nonce
};
use p256::{
    ecdh::EphemeralSecret, EncodedPoint, PublicKey, SecretKey
};

use rayon::prelude::*;
use sha2::{Sha256, Digest};
use p256::ecdsa::VerifyingKey;

fn generate_keypair() -> (SecretKey, PublicKey) {
    let secret = SecretKey::random(&mut OsRng);
    let public = secret.public_key();
    (secret, public)
}

fn derive_shared_secret(ephemeral_secret: EphemeralSecret, peer_public: &PublicKey) -> [u8; 32] {
    let shared = ephemeral_secret.diffie_hellman(&peer_public);
    let mut hasher = Sha256::new();
    hasher.update(shared.raw_secret_bytes());
    hasher.finalize().into()
}

fn encrypt_message(
    plaintext: &[u8],
    receiver_public_key: &PublicKey,
) -> (Vec<u8>, [u8; 12], EncodedPoint) {
    let ephemeral_secret = EphemeralSecret::random(&mut OsRng);
    let ephemeral_public = EncodedPoint::from(ephemeral_secret.public_key());

    let shared_Secret = derive_shared_secret(ephemeral_secret, receiver_public_key);

    let aes_key = aes_gcm::Key::<Aes256Gcm>::from_slice(&shared_Secret);
    let cipher = Aes256Gcm::new(aes_key);

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&mut nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .expect("Encryption failed");

    (ciphertext, nonce_bytes, ephemeral_public)
}


fn decrypt_message(
    ciphertext: &[u8],
    nonce: &[u8; 12],
    ephemeral_public: &EncodedPoint,
    receiver_secret_key: EphemeralSecret,
) -> Vec<u8> {
    let peer_public = PublicKey::from_sec1_bytes(ephemeral_public   .as_bytes())
    .expect("invalid ephemeral public key");

    let shared_secret = derive_shared_secret(EphemeralSecret::from(receiver_secret_key), &peer_public);

    let aes_key = aes_gcm::Key::<Aes256Gcm>::from_slice(&shared_secret);
    let cipher = Aes256Gcm::new(aes_key);
    cipher.decrypt(Nonce::from_slice(nonce), ciphertext).expect("Decryption failed")
}

fn main() {
    println!("{:?}", generate_keypair())
}
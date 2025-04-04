use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use p256::{
    ecdh::EphemeralSecret, EncodedPoint, PublicKey, SecretKey
};
use rand_core::RngCore;
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use p256::ecdsa::VerifyingKey;

fn generate_keypair() -> (SecretKey, PublicKey) {
    let secret = SecretKey::random(&mut OsRng);
    let public = secret.public_key();
    (secret, public)
}

fn main() {
    println!("{:?}", generate_keypair())
}
// src/models/mod.rs

pub mod user;
pub mod blacklist;


pub struct EncryptedPayload {
    pub ciphertext: Vec<u8>,
    pub ephemeral_public_key: Vec<u8>,
}


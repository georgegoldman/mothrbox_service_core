// src/models/mod.rs

pub struct EncryptedPayload {
    pub ciphertext: Vec<u8>,
    pub ephemeral_public_key: Vec<u8>,
}

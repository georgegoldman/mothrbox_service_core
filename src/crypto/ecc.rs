use p256::{
    ecdh::{EphemeralSecret, SharedSecret},
    PublicKey,
};
use aes_gcm::{
    aead::{Aead, KeyInit, generic_array::GenericArray},
    Aes256Gcm, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use std::error::Error;

/// Struct that holds the encrypted result and ephemeral key
pub struct EncryptedPayload {
    pub ciphertext: Vec<u8>,
    pub ephemeral_public_key: Vec<u8>,
}

/// Public struct exposing only safe encryption/decryption methods
pub struct ECCrypto;

impl ECCrypto {
    /// Encrypts data using ECC + AES-GCM
    pub fn encrypt(
        plain_text: &[u8],
        recipient_public_key: &PublicKey,
    ) -> Result<EncryptedPayload, Box<dyn Error>> {
        let (ephemeral_secret, ephemeral_public) = Self::generate_ephemeral_key_pair();

        let shared_secret = Self::derive_shared_secret(&ephemeral_secret, recipient_public_key);
        let aes_key = GenericArray::from_slice(&shared_secret.raw_secret_bytes()[..32]);
        let cipher = Aes256Gcm::new(aes_key);

        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let nonce = Nonce::from_slice(&nonce);

        let ciphertext = cipher.encrypt(nonce, plain_text)?;

        let mut full_ciphertext = nonce.to_vec();
        full_ciphertext.extend(ciphertext);

        Ok(EncryptedPayload {
            ciphertext: full_ciphertext,
            ephemeral_public_key: ephemeral_public.to_sec1_bytes().to_vec(),
        })
    }

    /// Decrypts the data using recipient's secret and sender's public key
    pub fn decrypt(
        recipient_secret: &EphemeralSecret,
        sender_public_key: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        if ciphertext.len() < 12 {
            return Err("Ciphertext too short".into());
        }

        let sender_public = PublicKey::from_sec1_bytes(sender_public_key)?;
        let shared_secret = Self::derive_shared_secret(recipient_secret, &sender_public);
        let aes_key = GenericArray::from_slice(&shared_secret.raw_secret_bytes()[..32]);
        let cipher = Aes256Gcm::new(aes_key);

        let (nonce_bytes, encrypted_data) = ciphertext.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let plain_text = cipher.decrypt(nonce, encrypted_data)?;
        Ok(plain_text)
    }

    // 🔒 Private helpers - not accessible outside this file

    fn generate_ephemeral_key_pair() -> (EphemeralSecret, PublicKey) {
        let secret_key = EphemeralSecret::random(&mut OsRng);
        let public_key = PublicKey::from(&secret_key);
        (secret_key, public_key)
    }

    fn derive_shared_secret(
        secret_key: &EphemeralSecret,
        other_public: &PublicKey,
    ) -> SharedSecret {
        secret_key.diffie_hellman(other_public)
    }
}

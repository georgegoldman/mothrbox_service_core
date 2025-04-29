use std::fs;
use std::path::Path;
use p256::{
    ecdh::{EphemeralSecret, SharedSecret},
    PublicKey,
};
use aes_gcm::{
    aead::{Aead, KeyInit, generic_array::GenericArray},
    Aes256Gcm, Nonce,
};
use rand::{RngCore, rngs::OsRng};
use anyhow::{Context, Result};



// Function to generate the ephemeral key pair
pub fn generate_key_pair() -> Result<(EphemeralSecret, PublicKey)> {
    let mut rng = OsRng;
    let secret = EphemeralSecret::random(&mut rng);
    let public = PublicKey::from(&secret);
    Ok((secret, public))
}

// Function to generate the shared secret using Diffie-Hellman
pub fn generate_shared_secret(
    ephemeral_secret: &EphemeralSecret,
    recipient_public: &PublicKey,
) -> Result<SharedSecret> {
    let shared_secret = ephemeral_secret.diffie_hellman(recipient_public);
    Ok(shared_secret)
}

// Function to get the recipient's public key from the ephemeral secret
pub fn get_recipient_public_key(ephemeral_secret: &EphemeralSecret) -> PublicKey {
    PublicKey::from(ephemeral_secret)
}

// Encrypts a file using AES-GCM with the generated shared secret
pub fn encrypt_file(
    input_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
    recipient_public: &PublicKey,
) -> Result<()> {
    let mut rng = OsRng;
    let (ephemeral_secret, ephemeral_public) = generate_key_pair()?;
    let shared_secret = generate_shared_secret(&ephemeral_secret, recipient_public)?;
    let shared_secret_bytes = shared_secret.raw_secret_bytes();
    let aes_key = GenericArray::from_slice(&shared_secret_bytes[..32]);
    let cipher = Aes256Gcm::new(aes_key);

    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);
    let nonce = Nonce::from_slice(&nonce);

    let plaintext = fs::read(input_path).context("Failed to read input file")?;
    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).context("Encryption failed")?;

    let mut output_data = ephemeral_public.to_sec1_bytes().to_vec();
    output_data.extend_from_slice(&nonce);
    output_data.extend(ciphertext);

    fs::write(output_path, output_data).context("Failed to write output file")?;

    Ok(())
}

// Decrypts a file using AES-GCM with the generated shared secret
pub fn decrypt_file(
    input_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
    recipient_secret: &EphemeralSecret,
) -> Result<()> {
    let encrypted_data = fs::read(input_path).context("Failed to read encrypted file")?;

    if encrypted_data.len() < 65 + 12 {
        return Err(anyhow::anyhow!("File too short to be valid encrypted data"));
    }

    let (ephemeral_public_bytes, rest) = encrypted_data.split_at(65);
    let (nonce_bytes, ciphertext) = rest.split_at(12);

    let ephemeral_public = PublicKey::from_sec1_bytes(ephemeral_public_bytes)
        .context("Invalid ephemeral public key")?;
    let shared_secret = recipient_secret.diffie_hellman(&ephemeral_public);
    let shared_secret_bytes = shared_secret.raw_secret_bytes();
    let aes_key = GenericArray::from_slice(&shared_secret_bytes[..32]);
    let cipher = Aes256Gcm::new(aes_key);
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher.decrypt(nonce, ciphertext).context("Decryption failed")?;

    fs::write(output_path, plaintext).context("Failed to write decrypted file")?;

    Ok(())
}

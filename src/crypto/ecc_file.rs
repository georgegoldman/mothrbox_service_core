
use std::fs;
use std::path::Path;
use aes::Aes256;
use p256::{
    ecdh::{EphemeralSecret, SharedSecret}, NistP256, PublicKey
};
use aes_gcm::{
    aead::{Aead, KeyInit, generic_array::GenericArray},
    Aes256Gcm, Nonce,
};
use rand::{RngCore, rngs::OsRng};



// Function to generate the ephemeral key pair
pub fn generate_key_pair() -> std::result::Result<(EphemeralSecret, PublicKey), std::io::Error> {
    let mut rng = OsRng;
    let secret = EphemeralSecret::random(&mut rng);
    let public = PublicKey::from(&secret);
    Ok((secret, public))
}

// Function to generate the shared secret using Diffie-Hellman
pub fn generate_shared_secret(
    ephemeral_secret: &EphemeralSecret,
    recipient_public: &PublicKey,
) -> Result<SharedSecret, std::io::Error> {
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
) -> Result<(), std::io::Error> {
    let mut rng = OsRng;
    let (ephemeral_secret, ephemeral_public) = generate_key_pair()?;
    let shared_secret = generate_shared_secret(&ephemeral_secret, recipient_public)?;
    let shared_secret_bytes = shared_secret.raw_secret_bytes();
    let aes_key = GenericArray::from_slice(&shared_secret_bytes[..32]);
    let cipher = Aes256Gcm::new(aes_key);

    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);
    let nonce = Nonce::from_slice(&nonce);

    let plaintext = fs::read(input_path).map_err(|e| {
        eprintln!("failed to read input file: {:?}", e);
        e
    })?;
    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).map_err(|e| {
        eprintln!("Encryption failed: {:?}", e);
        std::io::Error::new(std::io::ErrorKind::Other, "Encryption Failed")
        
    })?;

    let mut output_data = ephemeral_public.to_sec1_bytes().to_vec();
    output_data.extend_from_slice(&nonce);
    output_data.extend_from_slice(&ciphertext);

    fs::write(output_path, output_data).map_err(|e| {
        eprintln!("Failed to write output file {:?}", e);
        e
    })?;

    Ok(())
}

pub fn encrypt_bytes(
    plaintext: &[u8],
    sender_key: &EphemeralSecret,
    recipient_public: &PublicKey,
) -> Result<Vec<u8>, std::io::Error> {
    let mut rng = OsRng;
    // let (ephemeral_secret, ephemeral_public) = generate_key_pair()?;
    let share_secret = generate_shared_secret(&sender_key, recipient_public)?;
    let shared_secret_bytes = share_secret.raw_secret_bytes();
    let aes_key = GenericArray::from_slice(&shared_secret_bytes[..32]);
    let cipher = Aes256Gcm::new(aes_key);

    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);
    let nonce = Nonce::from_slice(&nonce);

    let ciphertext = cipher.encrypt(nonce, plaintext).map_err(|_e| {
        std::io::Error::new(std::io::ErrorKind::Other, "Encryption Failed")
    }) ?;

    let mut output_data = recipient_public.to_sec1_bytes().to_vec();
    output_data.extend_from_slice(&nonce);
    output_data.extend_from_slice(&ciphertext);

    Ok(output_data)
}

pub fn decrypt_bytes(
    plaintext: &[u8],
    recipient_secret: &EphemeralSecret
) -> Result<Vec<u8>, std::io::Error> {

    if plaintext.len() < 65 + 12 {
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "File too short to be valid enctypted data"));
    }

    let (ephemeral_public_bytes, rest) = plaintext.split_at(65);
    let (nonce_bytes, ciphertext) = rest.split_at(12);

    let ephemeral_public = PublicKey::from_sec1_bytes(ephemeral_public_bytes)
    .map_err(|e| {
        eprintln!("Invalid ephemeral public key {:?}", e);
        std::io::Error::new(std::io::ErrorKind::Other, "Invalid Ephemeral public key")
    })?;
    let shared_secret = recipient_secret.diffie_hellman(&ephemeral_public);
    let shared_secret_bytes = shared_secret.raw_secret_bytes();

    let aes_key = GenericArray::from_slice(&shared_secret_bytes[..32]);

    let cipher = Aes256Gcm::new(aes_key);
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_e| {
        std::io::Error::new(std::io::ErrorKind::Other, "Decryption failed")
    })?;
    Ok(plaintext)
}

// Decrypts a file using AES-GCM with the generated shared secret
pub fn decrypt_file(
    input_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
    recipient_secret: &EphemeralSecret,
) -> Result<(), std::io::Error> {
    let encrypted_data = fs::read(input_path).map_err(|e|  {
        eprintln!("Failed to read encrypted file {:?}", e);
        e
    })?;

    if encrypted_data.len() < 65 + 12 {
        return Err(std::io::Error::new( std::io::ErrorKind::Other, "File too short to be valid encrypted data"));
    }

    let (ephemeral_public_bytes, rest) = encrypted_data.split_at(65);
    let (nonce_bytes, ciphertext) = rest.split_at(12);

    let ephemeral_public = PublicKey::from_sec1_bytes(ephemeral_public_bytes)
        .map_err(|e| {
            eprintln!("Invalid ephemeral public key {:?}", e);
            std::io::Error::new(std::io::ErrorKind::Other, "Invalid ephemeral public key")
        })?;
    let shared_secret = recipient_secret.diffie_hellman(&ephemeral_public);
    let shared_secret_bytes = shared_secret.raw_secret_bytes();
    let aes_key = GenericArray::from_slice(&shared_secret_bytes[..32]);
    let cipher = Aes256Gcm::new(aes_key);
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|e| {
        eprintln!("Decryption failed {:?}", e);
        std::io::Error::new(std::io::ErrorKind::Other, "Decryption failed")
    })?;

    fs::write(output_path, plaintext).map_err(|e| {
        eprintln!("Failed to write decrypted file {:?}", e);
        e
    })?;

    Ok(())
}
use p256::{
    ecdh::{EphemeralSecret, SharedSecret}, PublicKey
};

use aes_gcm::{
    aead::{Aead, KeyInit, generic_array::GenericArray},
    Aes256Gcm, Nonce
};
use rand:: {RngCore, rngs::OsRng};
use hex;
use sha2::digest::generic_array::sequence::GenericSequence;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let message = "This is a secret message to encrypt with ecc";
    // Alice generates an ephemeral secret key and public key
    let (a_secret, a_pub) = generate_ephemeria_key_pair();
    
    // Bob generates an ephemeral secret key and public key
    let (b_secret, b_pub) = generate_ephemeria_key_pair();
    
    println!("Alice public key: {}", hex::encode(a_pub.to_sec1_bytes()));
    println!("Bob public key: {}", hex::encode(b_pub.to_sec1_bytes()));

    let (cipher_text, ephemeral_public) = ecc_encrypt(message.as_bytes(), &b_pub)?;

    println!("\nencrypted message {}", hex::encode(&cipher_text));

    // bob decrypt the message

    let decrypted = ecc_decrypt(&b_secret, &ephemeral_public, &cipher_text)?;

    println!("\nDecrypt message: {}", String::from_utf8(decrypted)?);
    
    // (e.g., with AES-GCM as shown in previous examples)
    
    Ok(())
}

fn generate_ephemeria_key_pair() -> (EphemeralSecret, PublicKey) {
    let secret_key = EphemeralSecret::random(&mut OsRng);
    let public_key= PublicKey::from(&secret_key);
    (secret_key, public_key)
}

fn generate_shared_secret(secret_key: EphemeralSecret, receiver_pub: PublicKey) -> SharedSecret {
    secret_key.diffie_hellman(&receiver_pub)
}

fn ecc_encrypt(
    plain_text: &[u8],
    recipient_public_key: &PublicKey,
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    let mut rng = OsRng;
    let (ephemeral_secret, ephemeral_public) = generate_ephemeria_key_pair();

    // Perform ECDH key exchange
    let share_secret = ephemeral_secret.diffie_hellman(recipient_public_key);

    // Derive AES key from shared secret (first 32 bytes)
    let shared_secret_bytes = share_secret.raw_secret_bytes();
    let aes_key = GenericArray::from_slice(&shared_secret_bytes[..32]);

    // initial AES-GCM cipher
    let cipher = Aes256Gcm::new(aes_key);

    // Generate random nonce (96 bits)
    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);
    let nonce = Nonce::from_slice(&nonce);

    // Encrypt the message
    let ciphertext = cipher.encrypt(&nonce, plain_text)?;

        // Combine nonce and ciphertext
    let mut full_ciphertext = nonce.to_vec();
    full_ciphertext.extend(ciphertext);

    // Return (ciphertext + nonce, ephemeral public key)
    Ok((full_ciphertext, ephemeral_public.to_sec1_bytes().to_vec()))

}

fn ecc_decrypt(
    recipient_secret: &EphemeralSecret,
    sender_public_key: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let sender_public = PublicKey::from_sec1_bytes(sender_public_key)?;

    // Perform ECDH key exchange
    let shared_secrete = recipient_secret.diffie_hellman(&sender_public);

    // Derive AES key
    let shared_secret_bytes = shared_secrete.raw_secret_bytes();
    let aes_key = GenericArray::from_slice(&shared_secret_bytes[..32]);

    // Initialize AES-GCM cipher
    let cipher = Aes256Gcm::new(aes_key);

    //split nonce (first 12 bytes) and actual ciphertext
    if ciphertext.len() < 12 {
        return Err("Ciphertext too short".into());
    }
    let (nonce_bytes, encrypted_data) = ciphertext.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    // Decrypt the message
    let plain_text = cipher.decrypt(nonce, encrypted_data)?;

    Ok(plain_text)
}
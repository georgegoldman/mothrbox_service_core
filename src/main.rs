// use p256::ecdh::EphemeralSecret;



// fn main() -> Result<(), Box<dyn std::error::Error>> {
//     let message = "This is a secret message to encrypt with ecc";
//     // Alice generates an ephemeral secret key and public key
//     let (a_secret, a_pub) = generate_ephemeria_key_pair();
    
//     // Bob generates an ephemeral secret key and public key
//     let (b_secret, b_pub) = generate_ephemeria_key_pair();
    
//     println!("Alice public key: {}", hex::encode(a_pub.to_sec1_bytes()));
//     println!("Bob public key: {}", hex::encode(b_pub.to_sec1_bytes()));

//     let (cipher_text, ephemeral_public) = ecc_encrypt(message.as_bytes(), &b_pub)?;

//     println!("\nencrypted message {}", hex::encode(&cipher_text));
//     // bob decrypt the message

//     let decrypted = ecc_decrypt(&b_secret, &ephemeral_public, &cipher_text)?;

//     println!("\nDecrypt message: {}", String::from_utf8(decrypted)?);
    
//     // (e.g., with AES-GCM as shown in previous examples)
    
//     Ok(())
// }


// src/main.rs

mod crypto;
mod models;

use crypto::ecc::ECCrypto;
use p256::{ecdh::EphemeralSecret, PublicKey};

fn main() {
    println!("ECC Encryption Demo");

    // Generate recipient key pair
    let recipient_secret = EphemeralSecret::random(&mut rand::rngs::OsRng);
    let recipient_public = PublicKey::from(&recipient_secret);

    // Message to encrypt
    let message = b"Hello, encrypted world!";

    // Encrypt
    match ECCrypto::encrypt(message, &recipient_public) {
        Ok(payload) => {
            println!("Encrypted message: {:?}", payload.ciphertext);
            println!("Ephemeral public key: {:?}", payload.ephemeral_public_key);

            // Decrypt
            match ECCrypto::decrypt(&recipient_secret, &payload.ephemeral_public_key, &payload.ciphertext) {
                Ok(decrypted) => {
                    println!("Decrypted message: {:?}", String::from_utf8(decrypted).unwrap());
                }
                Err(e) => {
                    eprintln!("Decryption failed: {}", e);
                }
            }
        }
        Err(e) => {
            eprintln!("Encryption failed: {}", e);
        }
    }
}


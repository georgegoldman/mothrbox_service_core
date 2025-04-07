// use p256::ecdh::EphemeralSecret;

#[macro_use]
extern crate rocket;

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

use crypto::ecc::ECCrypto;
use p256::{ecdh::EphemeralSecret, PublicKey};
use crypto::ecc_file;

use crypto::ecc_file::{generate_key_pair, encrypt_file, decrypt_file};
use anyhow::Result;

use models::user;
use rocket::{custom, route, routes};
use rocket_cors::{AllowedOrigins, CorsOptions};
mod db;
mod routes;
mod models;

// fn main() {
//     println!("ECC Encryption Demo");

//     // Generate recipient key pair
//     let recipient_secret = EphemeralSecret::random(&mut rand::rngs::OsRng);
//     let recipient_public = PublicKey::from(&recipient_secret);

//     // Message to encrypt
//     let message = b"Hello, encrypted world!";

//     // Encrypt
//     match ECCrypto::encrypt(message, &recipient_public) {
//         Ok(payload) => {
//             println!("Encrypted message: {:?}", payload.ciphertext);
//             println!("Ephemeral public key: {:?}", payload.ephemeral_public_key);

//             // Decrypt
//             match ECCrypto::decrypt(&recipient_secret, &payload.ephemeral_public_key, &payload.ciphertext) {
//                 Ok(decrypted) => {
//                     println!("Decrypted message: {:?}", String::from_utf8(decrypted).unwrap());
//                 }
//                 Err(e) => {
//                     eprintln!("Decryption failed: {}", e);
//                 }
//             }
//         }
//         Err(e) => {
//             eprintln!("Encryption failed: {}", e);
//         }
//     }
// }

// fn main() -> Result<()> {
//     let (sender_secret, sender_public) = generate_key_pair()?;
//     let (recipient_secret, recipient_public) = generate_key_pair()?;

//     let input_file = "/home/goldman/mothrbox/DSC08666.jpg";
//     let encrypted_file= "encrypted.enc";
//     let decrypted_file = "/home/goldman/mothrbox/decrypted.jpg";

//     encrypt_file(input_file, encrypted_file, &recipient_public)?;
//     println!("File encrypted successfully");

//     decrypt_file(encrypted_file, decrypted_file, &recipient_secret)?;
//     println!("File decrypted successfully");

//     Ok(())
// }



#[launch]
async fn rocket() -> _ {
    use std::env;
    let user_db = db::connect::<models::user::User>().await;
    let blacklisted_tokens_db = db::connect::<models::blacklist::BlackListedToken>().await;

    let port = env::var("PORT")
    .unwrap_or_else(|_| "8000".to_string())
    .parse::<u16>()
    .expect("Invalid port number");

    let cors = CorsOptions::default()
    .allowed_origins(AllowedOrigins::all())
    .to_cors()
    .unwrap();

    rocket::custom(
        rocket::Config {
            address: "0.0.0.0".parse().unwrap(),
            port,
            ..rocket::Config::default()
        }
    )
    .attach(cors)
    .manage(user_db)
    .manage(blacklisted_tokens_db)
    .mount(
        "/api/v1",
        routes![
            routes::sign_up,
            routes::read_users,
            routes::drop_user,
            routes::update_user,
            routes::read_user,
            routes::login,
            routes::profile,
            routes::delete_all_users,

        ]
    )
}
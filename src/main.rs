#[macro_use]
extern crate rocket;
use std::path::Path;
use dotenv::dotenv;
use std::env;

use crate::crypto::ecc_file::{ generate_key_pair, encrypt_file, decrypt_file, encrypt_large_file };
// use route::post_video;
use std::process::Command;



mod crypto;
mod paste_id;
mod models;
mod endpoints;
mod db;
mod dto;
mod middleware;
mod sui_core;
mod walrus_core;

use rocket_cors::{AllowedOrigins, CorsOptions};
fn _test_encrytion()
{
     // 1. Generate key pair (recipient)
     let (recipient_secret, recipient_public) = generate_key_pair().expect("Key pair generation failed");

     // 2. Paths for testing
     let input_path = Path::new("/home/goldman/mothrbox/src/routes.rs");
     let encrypted_path = Path::new("/home/goldman/mothrbox/src/routes.rs");
     let decrypted_path = Path::new("/home/goldman/mothrbox/src/route.rs");
 
     // 3. Write something to input file
    //  std::fs::write(&input_path, b"Hello, secure world!").expect("Failed to write test input");
 
     // 3. Encrypt
     encrypt_file(&input_path, &encrypted_path, &recipient_public).expect("Encryption failed");
 
     // 4. Decrypt
     decrypt_file(&encrypted_path, &decrypted_path, &recipient_secret).expect("Decryption failed");
 
     // 5. Compare input and output
     let original = std::fs::read_to_string(&input_path).unwrap();
     let decrypted = std::fs::read_to_string(&decrypted_path).unwrap();
     assert_eq!(original, decrypted);
     println!("✅ Test passed. Decrypted output matches original input.");
}


#[launch]
async fn rocket() -> _ {
         let uname = Command::new("uname").arg("-a").output().unwrap();
    println!("OS Info: {}", String::from_utf8_lossy(&uname.stdout));

    let arch = Command::new("arch").output().unwrap();
    println!("Architecture: {}", String::from_utf8_lossy(&arch.stdout));
     dotenv().ok();

     // connect the different database collections
     let token_collection = db::connect::<models::ApiToken>().await;
     let keypair_collection = db::connect::<models::KeyPair>().await;

     let port  = env::var("PORT")
          .unwrap_or_else(|_| "7000".to_string())
          .parse::<u16>()
          .expect("Invalid PORT number");
     let cors = CorsOptions::default()
     .allowed_origins(AllowedOrigins::all())
     .to_cors()
     .unwrap();

     rocket::custom(rocket::Config {
          address: "0.0.0.0".parse().unwrap(),
          port,
          ..rocket::Config::default()
     })
     .attach(cors)
     .manage(token_collection)
     .manage(keypair_collection)
     .mount("/engine/core", routes![
          endpoints::upload_file,
          endpoints::decrypt_endpoint,
          endpoints::keypair,
          endpoints::create_keypair,
          endpoints::issue_token,
          endpoints::get_all_keypair,
          endpoints::walrus_test,
          endpoints::sui_test,
          endpoints::spawn_user,
          ])
     
}
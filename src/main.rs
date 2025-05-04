#[macro_use] extern crate rocket;
use std::path::Path;

use mothrbox::crypto::ecc_file::{ generate_key_pair, encrypt_file, decrypt_file };
// use route::post_video;

mod crypto;
mod route;
mod paste_id;

use  paste_id::PasteId;
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
fn rocket() -> _ {
     rocket::build().mount("/", routes![
          route::index, 
          route::retrieve, 
          route::upload_file,
          route::decrypt_endpoint,
          route::keypair,
          ])
}
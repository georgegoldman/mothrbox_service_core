use std::{borrow::Cow, path::Path};
use aes_gcm::Nonce;
use generic_array::GenericArray;
use mothrbox::crypto::ecc_file::{generate_key_pair, generate_shared_secret};
use p256::PublicKey;
// use aes_gcm::aes;
use rocket::{data::ToByteUnit, fs::TempFile, http::uri::Absolute, response::stream::ByteStream, tokio::fs::File, Data};
use rocket::response::content::RawMsgPack;
use tokio::io::AsyncReadExt;
use crate::paste_id::PasteId;

use aes::Aes256;
use ctr::Ctr128BE;
use cipher::{KeyIvInit, StreamCipher};
use rand::{rngs::OsRng, RngCore};

type Aes256Ctr = Ctr128BE<Aes256>;



#[get("/")]
pub fn index() -> &'static str {

    "USAGE

      POST /

          accepts raw data in the body of the request and responds with a URL of
          a page containing the body's content

      GET /<id>

          retrieves the content for the paste with id `<id>`"
}

#[get("/<id>")]
pub async fn retrieve(id: PasteId<'_>) -> Option<File> {
    File::open(id.file_path()).await.ok()
}




// we implement the upload route in main
const ID_LENGTH: usize = 3;
const HOST: Absolute<'static> = uri!("http://localhost:8000");

#[post("/", data= "<paste>")]
pub async fn upload(paste: rocket::Data<'_>) -> std::io::Result<String> {
    let id = PasteId::new(ID_LENGTH);
    paste.open(128.kibibytes()).into_file(id.file_path()).await?;
    Ok(uri!(HOST, retrieve(id)).to_string())
}

#[post("/upload", data =  "<data>")]
pub async fn upload_file( data: Data<'_>) -> std::io::Result<RawMsgPack<Vec<u8>>> {
        // Read the file into memory (limit: 10MB for safety)
        let mut input_data = Vec::new();
        data.open(10.megabytes()).read_to_end(&mut input_data).await?;
    
        // Generate a random key and nonce (you can also use a fixed one for testing)
        let (ephemeral_secret, ephemeral_public) = generate_key_pair().expect("Key pair generation failed");
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 16];
        OsRng.fill_bytes(&mut key);
        OsRng.fill_bytes(&mut nonce);
    
        // Encrypt in-place
        let mut cipher = Aes256Ctr::new(&key.into(), &nonce.into());
        let mut encrypted_data = input_data.clone();
        cipher.apply_keystream(&mut encrypted_data);
    
        // Prepend nonce to the ciphertext (so it can be decrypted later)
        let mut result = nonce.to_vec();
        result.extend(encrypted_data);
    
        // Return as downloadable binary file
        Ok(RawMsgPack(result))

}


use std::{borrow::Cow, path::Path};
use aes_gcm::Nonce;
use base64::engine::general_purpose;
use base64::Engine;
use generic_array::GenericArray;
use mothrbox::crypto::ecc_file::{decrypt_bytes, encrypt_bytes, encrypt_file, generate_key_pair, generate_shared_secret};
use p256::elliptic_curve::PublicKey;
use p256::NistP256;
use rocket::serde::json::Json;
// use aes_gcm::aes;
use rocket::{data::ToByteUnit, fs::TempFile, http::uri::Absolute, response::stream::ByteStream, tokio::fs::File, Data};
use rocket::response::content::RawMsgPack;
use serde::Serialize;
use tokio::io::AsyncReadExt;
use tokio::stream;
use crate::crypto::ecc_file::get_recipient_public_key;
use crate::paste_id::PasteId;

use aes::Aes256;
use ctr::Ctr128BE;
use cipher::{KeyIvInit, StreamCipher};
use rand::{rngs::OsRng, RngCore};
use std::io;



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
// const ID_LENGTH: usize = 3;
// const HOST: Absolute<'static> = uri!("http://localhost:8000");

// #[post("/", data= "<paste>")]
// pub async fn upload(paste: rocket::Data<'_>) -> std::io::Result<String> {
//     let id = PasteId::new(ID_LENGTH);
//     paste.open(128.kibibytes()).into_file(id.file_path()).await?;
//     Ok(uri!(HOST, retrieve(id)).to_string())
// }

#[derive(Serialize)]
pub struct KeyPairResponse {
    pub private_key: String,
    pub public_key: String,
}
#[get("/keypair")]
pub fn keypair() -> Result<Json<KeyPairResponse>, std::io::Error> {
    let (  private_key, public_key) = generate_key_pair()?;

    // key to base64
    let shared_secret = private_key.diffie_hellman(&public_key);
    let private_bytes = shared_secret.raw_secret_bytes(); // [u8, 32]
    let public_bytes = public_key.to_sec1_bytes();


    let private_b64 = general_purpose::STANDARD.encode(private_bytes);
    let public_b64 = general_purpose::STANDARD.encode(&public_bytes);

    Ok(Json(
        KeyPairResponse { private_key: private_b64, public_key: public_b64 }
    ))


}



#[post("/encrypy_file", data =  "<data>")]
pub async fn upload_file( data: Data<'_>) -> std::io::Result<RawMsgPack<Vec<u8>>>{
    let mut buffer = Vec::new();
    let mut stream = data.open(5.mebibytes()); // size limit will be changed
    stream.read_to_end(&mut buffer).await?;
    

    let (  signer_private_key, recipient_public) = generate_key_pair().expect("Key pair generation failed");
    match encrypt_bytes(&buffer, &signer_private_key, &recipient_public) {
        Ok((encrypted_data)) => Ok(RawMsgPack(encrypted_data)),
        Err(e) => Err(e)
    }

}


#[post("/decrypt", data = "<data>")]
pub async fn decrypt_endpoint(data: Data<'_>) -> Result<RawMsgPack<Vec<u8>>, io::Error> {
    let mut buffer = Vec::new();
    let mut stream = data.open(10.megabytes()); // Adjust size limit as needed
    stream.read_to_end(&mut buffer).await?;

    // You must get or derive this securely. Here, we assume it's available.
    let (recipient_secret, _) = generate_key_pair().expect("key generation failed"); // Replace with real logic

    match decrypt_bytes(&buffer, &recipient_secret) {
        Ok(plaintext) => Ok(RawMsgPack(plaintext)),
        Err(e) => {
            eprintln!("Decryption error: {:?}", e);
            Err(io::Error::new(io::ErrorKind::Other, "Decryption failed"))
        }
    }
}


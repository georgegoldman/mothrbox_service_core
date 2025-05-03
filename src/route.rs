use std::{borrow::Cow, path::Path};
use aes_gcm::Nonce;
use generic_array::GenericArray;
use mothrbox::crypto::ecc_file::{encrypt_bytes, encrypt_file, generate_key_pair, generate_shared_secret};
use p256::elliptic_curve::PublicKey;
// use aes_gcm::aes;
use rocket::{data::ToByteUnit, fs::TempFile, http::uri::Absolute, response::stream::ByteStream, tokio::fs::File, Data};
use rocket::response::content::RawMsgPack;
use tokio::io::AsyncReadExt;
use tokio::stream;
use crate::crypto::ecc_file::get_recipient_public_key;
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
    let mut buffer = Vec::new();
    let mut stream = data.open(5.mebibytes()); // size limit will be changed
    stream.read_to_end(&mut buffer).await?;

    let (_, recipient_public) = generate_key_pair().expect("Key pair generation failed");

    match encrypt_bytes(&buffer, &recipient_public) {
        Ok(encrypted_data) => Ok(RawMsgPack(encrypted_data)),
        Err(e) => Err(e)
    }

}


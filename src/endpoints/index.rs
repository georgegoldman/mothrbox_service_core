use base64::engine::general_purpose;
use base64::Engine;
use chrono::Utc;
use futures::io::Cursor;
use futures::TryStreamExt;
use generic_array::GenericArray;
use mongodb::bson::doc;
use mongodb::bson::oid::{self, ObjectId};
use mongodb::{results, Collection};
use crate::crypto::ecc_file::{decrypt_bytes, encrypt_bytes, encrypt_file, encrypt_large_file, generate_key_pair, generate_shared_secret};
use crate::crypto::orion_encryption::{create_key, nonce};
use orion::aead::streaming::Nonce;
use orion::hazardous::aead::xchacha20poly1305;
use p256::elliptic_curve::ff::derive::bitvec::view::AsBits;
use p256::elliptic_curve::PublicKey;
use p256::NistP256;
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::State;
// use aes_gcm::aes;
use rocket::{data::ToByteUnit, fs::TempFile, http::uri::Absolute, response::stream::ByteStream, tokio::fs::File, Data};
use rocket::response::content::RawMsgPack;
use serde::Serialize;
use tokio::io::AsyncReadExt;
use tokio::stream;
use crate::crypto::ecc_file::get_recipient_public_key;
use crate::crypto::orion_encryption::{encrypt_core};
use crate::dto::key::KeyPairDTO;
use crate::dto::GenerateKeypairRequest;
use crate::middleware::api_token::AuthenticatedClient;
use crate::models::api_token::ApiToken;
use crate::models::key::KeyPair;
use crate::paste_id::PasteId;
use crate::sui_core;
use crate::walrus_core::walrus_impl;

use aes::Aes256;
use ctr::Ctr128BE;
use cipher::{KeyIvInit, StreamCipher};
use rand::{rngs::OsRng, RngCore};
use std::io;
use std::fmt;



type Aes256Ctr = Ctr128BE<Aes256>;

#[post("/spawn/<username>")]
pub async fn spawn_user(username: &str) -> &'static str {
    let client = kube::Client::try_default().await.unwrap();
    let pods: kube::Api<k8s_openapi::api::core::v1::Pod> = kube::Api::default_namespaced(client.clone());
    let pvcs: kube::Api<k8s_openapi::api::core::v1::PersistentVolumeClaim> = kube::Api::default_namespaced(client);

    let pvc_name = format!("pvc-{}", username);
    let pod_name = format!("user-{}", username);

    let pvc = serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": { "name": pvc_name },
        "spec": {
            "accessModes": ["ReadWriteOnce"],
            "resources": { "requests": { "storage": "1Gi" } },
            "storageClassName": "azurefile"
        }
    })).unwrap();

    let pod = serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": { "name": pod_name },
        "spec": {
            "containers": [{
                "name": "cli-container",
                "image": "yourdockerhub/cli-service:latest",
                "args": ["while", "true", ";", "do", "sleep", "30", ";", "done;"],
                "volumeMounts": [{
                    "name": "user-data",
                    "mountPath": "/data"
                }]
            }],
            "volumes": [{
                "name": "user-data",
                "persistentVolumeClaim": {
                    "claimName": pvc_name
                }
            }]
        }
    })).unwrap();

    let _ = pvcs.create(&Default::default(), &pvc).await;
    let _ = pods.create(&Default::default(), &pod).await;
    "User environment spawned"
}

#[get("/walrus_test")]
pub fn walrus_test() -> Result<String, rocket::response::status::Custom<String>> {
    let walrus_init = walrus_impl::WalrusCore{};

    match walrus_init.store(
        "/home/goldman/mothrbox/dummy.mp4",
        "/home/goldman/mothrbox/client_config.yaml",
        "/home/goldman/.sui/sui_config/client.yaml"
    ) {
        Ok(output) => Ok(output),
        Err(e) => Err(rocket::response::status::Custom(
            Status::InternalServerError,
            format!("Command failed: {}", e),
        )),
    }
}

#[get("/sui_test")]
pub fn sui_test() -> Result<String, rocket::response::status::Custom<String>> {
    let sui_init = sui_core::SuiCli{};

    match sui_init.get_active_wallet() {
        Ok(output) => Ok(output),
        Err(e) => Err(rocket::response::status::Custom(
            Status::InternalServerError,
            format!("Command failed {}", e)
        ))
    }
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

// #[derive(Serialize)]
// pub struct KeyPairResponse {
//     pub private_key: Key,
//     pub public_key: Key,
// }

#[get("/keypair/<key_pair_id>")]
pub async fn keypair(
    key_pair_id: &str,
    db: &State<Collection<KeyPair>>,
    _client: AuthenticatedClient
) ->
 Result<Json<KeyPair>, Status> 
{
    

    let object_id  = match ObjectId::parse_str(&key_pair_id) {
        Ok(oid) => oid,
        Err(_) => return  Err(Status::BadRequest),
    };

    let filter = mongodb::bson::doc! {"_id": object_id};
    let result = db.find_one(filter, None).await;
    eprintln!("logging...{:?}", result);
    match result {
        Ok(fetched_data) => {
            if let Some(data) = fetched_data {
                Ok(Json(data))
            } else {
                Err(Status::NotFound)
            }
        }
        Err(_) => Err(Status::InternalServerError)
    }

}

#[get("/keypair")]
pub async  fn get_all_keypair(
    db: &State<Collection<KeyPair>>,
    _client: AuthenticatedClient
) -> 
Json<Vec<KeyPair>> {
    let mut cursor: mongodb::Cursor<KeyPair> = db
    .find(doc! {}, None)
    .await
    .expect("Failed to get key pairs");
    let mut keypairs: Vec<KeyPair> = Vec::new();
    while let Some(key_pair) = cursor.try_next().await.expect("Error iteracting cursor") {
        keypairs.push(key_pair);
    }
    Json(keypairs)
}

#[post("/issue-token", data = "<wallet_address>")]
pub async fn issue_token(
    db: &State<Collection<ApiToken>>,
    wallet_address: Json<KeyPairDTO>
) -> Result<String, Status>
{
    let token = uuid::Uuid::new_v4().to_string();
    let now  = chrono::Utc::now();

    let new_token = ApiToken {
        id: ObjectId::new(),
        token: token.clone(),
        allowed: true,
        owner: wallet_address.address,
        created_at: Some(now.into()),
        expires_at: None
    };

    db.insert_one(&new_token, None)
    .await
    .map_err(|_| Status::InternalServerError)?;

    Ok(token)
}

#[post("/generate-keypairs", data="<key_data>")]
pub async fn create_keypair(
    db: &State<Collection<KeyPair>>,
    key_data: Json<GenerateKeypairRequest>
) -> 
rocket::response::status::Custom<Json<String>>
{
    let nonce = nonce();
    let secret_key = create_key(key_data.password.clone(), nonce);
    let key_bytes = secret_key.unprotected_as_bytes();
    let key_hex = hex::encode(key_bytes);

    // key to base64
    // let shared_secret: p256::elliptic_curve::ecdh::SharedSecret<NistP256> = private_key.diffie_hellman(&public_key);
    // let private_bytes = shared_secret.raw_secret_bytes(); // [u8, 32]
    // let public_bytes = public_key.to_sec1_bytes();

    
    // let private_b64 = general_purpose::STANDARD.encode(private_bytes);
    // let public_b64 = general_purpose::STANDARD.encode(&public_bytes);
    let now  = mongodb::bson::DateTime::from_chrono(Utc::now());
    let user_object_id  = match ObjectId::parse_str(&key_data.user) {
        Ok(oid) => oid,
        Err(_) => return  rocket::response::status::Custom(
            Status::InternalServerError,
            Json("user object id convertion failed".to_string())
        ),
    };
    let new_keypair = KeyPair {
        id: None,
        user: user_object_id,
        algorithm: Some(key_data.algorithm.clone()),
        is_active: true,
        secret_key: key_hex,
        created_at: Some(now),
        updated_at: Some(now),
    };

    match db.insert_one(new_keypair, None).await {
        Ok(_) => rocket::response::status::Custom(
            Status::Created,
            Json("Key pairs create successfully".to_string(),)
        ),
        Err(_) => rocket::response::status::Custom(
            Status::InternalServerError,
            Json("Failed to create key pairs".to_string())
        )
    }
}



#[post("/encrypt_file/<user_id>", data =  "<data>")]
pub async fn upload_file( 
    data: Data<'_>,
    // _client: AuthenticatedClient,
    user_id: &str,
    db: &State<Collection<KeyPair>>
) -> std::io::Result<RawMsgPack<Vec<u8>>> {
    let mut buffer = Vec::new();
    let mut stream = data.open(5.mebibytes());
    stream.read_to_end(&mut buffer).await?;
    
    let object_id  = match ObjectId::parse_str(&user_id) {
        Ok(oid) => oid,
        Err(err) => return Err(std::io::Error::new(std::io::ErrorKind::Other, err)),
    };

    let filter = mongodb::bson::doc! {"user": object_id};
    
    return Ok(RawMsgPack(buffer))
    // match db.find_one(filter, None).await {
    //     Ok(Some(keypair)) => {
    //         let key_hex_from_db = keypair.secret_key;
    //         let key_bytes = hex::decode(key_hex_from_db).unwrap();
    //         let key = orion::hazardous::aead::xchacha20poly1305::SecretKey::from_slice(&key_bytes).unwrap();
    //         let encrypted_data = encrypt_core(
    //             buffer.clone(),
    //             &buffer,
    //             &key,
    //             Nonce::generate()
    //         )
    //             .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    //         Ok(RawMsgPack(encrypted_data))
    //     },
    //     Ok(None) => Err(std::io::Error::new(std::io::ErrorKind::NotFound, "Keypair not found")),
    //     Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
    // }
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


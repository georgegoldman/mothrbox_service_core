use base64::engine::general_purpose;
use base64::Engine;
use chrono::Utc;
use futures::io::Cursor;
use futures::TryStreamExt;
use generic_array::GenericArray;
use mongodb::bson::doc;
use mongodb::bson::oid::{self, ObjectId};
use mongodb::{results, Collection};
use mothrbox_service_core::crypto::new_encryption::KeyPairDocument;
use crate::crypto::ecc_file::{decrypt_bytes, encrypt_bytes, encrypt_file, encrypt_large_file, generate_key_pair, generate_shared_secret};
use crate::crypto::new_encryption::{ApiResponse, CreateKeyRequest, EccKeyManager, KeyListResponse, SignRequest, VerifyRequest};
use crate::crypto::orion_encryption::{ nonce};
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

#[post("/keys", data = "<request>")]
pub async fn create_key(
    key_manager: &State<EccKeyManager>,
    request: Json<CreateKeyRequest>,
) -> Json<ApiResponse<String>> {
    match key_manager.save_key_pair(
        &request.key_id,
        request.curve_type.clone(),
        request.description.clone(),
    ).await {
        Ok(id) => Json(ApiResponse::success(id)),
        Err(e) => Json(ApiResponse::error(e.to_string())),
    }
}


#[get("/keys")]
pub async fn list_keys(
    key_manager: &State<EccKeyManager>,
) -> Json<ApiResponse<KeyListResponse>> {
    match key_manager.list_keys().await {
        Ok(keys) => {
            let total = keys.len();
            Json(ApiResponse::success(KeyListResponse { keys, total }))
        }
        Err(e) => Json(ApiResponse::error(e.to_string())),
    }
}


#[get("/keys/<key_id>/exists")]
pub async fn key_exists(
    key_manager: &State<EccKeyManager>,
    key_id: &str,
) -> Json<ApiResponse<bool>> {
    match key_manager.key_exists(key_id).await {
        Ok(exists) => Json(ApiResponse::success(exists)),
        Err(e) => Json(ApiResponse::error(e.to_string())),
    }
}

#[post("/keys/sign", data = "<request>")]
pub async fn sign_message(
    key_manager: &State<EccKeyManager>,
    request: Json<SignRequest>,
) -> Json<ApiResponse<String>> {
    // Decode base64 message
    let message = match base64::decode(&request.message) {
        Ok(msg) => msg,
        Err(e) => return Json(ApiResponse::error(format!("Invalid base64 message: {}", e))),
    };

    // Load key pair
    let key_pair = match key_manager.load_key_pair(&request.key_id).await {
        Ok(Some(kp)) => kp,
        Ok(None) => return Json(ApiResponse::error("Key not found".to_string())),
        Err(e) => return Json(ApiResponse::error(e.to_string())),
    };

    // Sign message
    match key_pair.sign(&message) {
        Ok(signature) => {
            let signature_b64 = base64::encode(&signature);
            Json(ApiResponse::success(signature_b64))
        }
        Err(e) => Json(ApiResponse::error(e.to_string())),
    }
}

#[post("/keys/verify", data = "<request>")]
pub async fn verify_signature(
    key_manager: &State<EccKeyManager>,
    request: Json<VerifyRequest>,
) -> Json<ApiResponse<bool>> {
    // Decode base64 inputs
    let message = match base64::decode(&request.message) {
        Ok(msg) => msg,
        Err(e) => return Json(ApiResponse::error(format!("Invalid base64 message: {}", e))),
    };

    let signature = match base64::decode(&request.signature) {
        Ok(sig) => sig,
        Err(e) => return Json(ApiResponse::error(format!("Invalid base64 signature: {}", e))),
    };

    // Load key pair
    let key_pair = match key_manager.load_key_pair(&request.key_id).await {
        Ok(Some(kp)) => kp,
        Ok(None) => return Json(ApiResponse::error("Key not found".to_string())),
        Err(e) => return Json(ApiResponse::error(e.to_string())),
    };

    // Verify signature
    match key_pair.verify(&message, &signature) {
        Ok(is_valid) => Json(ApiResponse::success(is_valid)),
        Err(e) => Json(ApiResponse::error(e.to_string())),
    }
}

#[delete("/keys/<key_id>")]
pub async fn delete_key(
    key_manager: &State<EccKeyManager>,
    key_id: &str,
) -> Json<ApiResponse<bool>> {
    match key_manager.delete_key_pair(key_id).await {
        Ok(deleted) => Json(ApiResponse::success(deleted)),
        Err(e) => Json(ApiResponse::error(e.to_string())),
    }
}

#[post("/keys/<key_id>/deactivate")]
pub async fn deactivate_key(
    key_manager: &State<EccKeyManager>,
    key_id: &str,
) -> Json<ApiResponse<bool>> {
    match key_manager.deactivate_key_pair(key_id).await {
        Ok(deactivated) => Json(ApiResponse::success(deactivated)),
        Err(e) => Json(ApiResponse::error(e.to_string())),
    }
}

#[get("/health")]
pub fn health_check() -> Json<ApiResponse<String>> {
    Json(ApiResponse::success("ECC Key Service is healthy".to_string()))
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



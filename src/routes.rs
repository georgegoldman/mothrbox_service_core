use actix_web::{
    web, HttpResponse, Error, error,
    http::StatusCode,
    post, get,
};
use actix_multipart::Multipart;
use anyhow::Ok;
use futures::{StreamExt, TryStreamExt};
use serde::{Serialize, Deserialize};
use std::sync::Mutex;
use std::collections::HashMap;
use std::io::Write;
use std::time::{Duration, Instant};
use uuid::Uuid;
use derive_more::{Display, Error};
use base64::{Engine as _, engine::general_purpose};
use tempfile::tempdir;
use log::{info, error};
use lazy_static::lazy_static;

// Import your crypto functions from the crypto module
use crate::crypto::ecc_file::{
    generate_key_pair, generate_shared_secret, get_recipient_public_key,
    encrypt_file, decrypt_file,
};
use p256::ecdh::EphemeralSecret;
use p256::PublicKey;

// Cache for storing ephemeral secrets
struct KeyCache {
    ephemeral_secrets: HashMap<String, (EphemeralSecret, Instant)>,
    ttl: Duration,
}

impl KeyCache {
    fn new(ttl_seconds: u64) -> Self {
        Self {
            ephemeral_secrets: HashMap::new(),
            ttl: Duration::from_secs(ttl_seconds),
        }
    }

    fn insert(&mut self, id: String, secret: EphemeralSecret) {
        self.clean_expired();
        self.ephemeral_secrets.insert(id, (secret, Instant::now()));
    }

    fn get(&mut self, id: &str) -> Option<&EphemeralSecret> {
        self.clean_expired();
        self.ephemeral_secrets.get(id).map(|(secret, _)| secret)
    }

    fn clean_expired(&mut self) {
        let now = Instant::now();
        self.ephemeral_secrets.retain(|_, (_, time)| {
            now.duration_since(*time) < self.ttl
        });
    }
}

lazy_static! {
    static ref KEY_CACHE: Mutex<KeyCache> = Mutex::new(KeyCache::new(3600)); // 1 hour TTL
}

// Custom error type for the API
#[derive(Debug, thiserror::Error)]
enum ApiError {
    #[error("Internal Server Error: {0}")]
    InternalError(String),
    
    #[error("Bad Request: {0}")]
    BadRequest(String),
    
    #[error("Not Found: {0}")]
    NotFound(String),
}

impl error::ResponseError for ApiError {
    fn status_code(&self) -> StatusCode {
        match *self {
            ApiError::InternalError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::NotFound(_) => StatusCode::NOT_FOUND,
        }
    }

    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code())
            .json(ErrorResponse {
                error: self.to_string(),
                status_code: self.status_code().as_u16(),
            })
    }
}

// Request and response models
#[derive(Serialize)]
struct KeyPairResponse {
    key_id: String,
    public_key: String,
}

#[derive(Deserialize)]
struct SharedSecretRequest {
    key_id: String,
    recipient_public_key: String,
}

#[derive(Serialize)]
struct SharedSecretResponse {
    shared_secret: String,
}

#[derive(Serialize)]
struct PublicKeyResponse {
    public_key: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    status_code: u16,
}

#[derive(Deserialize)]
struct EncryptionRequest {
    recipient_public_key: String,
}

// API handlers

// Generate a new key pair and return the public key with a key ID
#[post("/key-pair")]
pub async fn generate_key_pair_handler() -> Result<HttpResponse, Error> {
    match generate_key_pair() {
        std::result::Result::Ok((secret, public)) => {
            let key_id = Uuid::new_v4().to_string();
            let public_key_bytes = public.to_sec1_bytes();
            let public_key_b64 = general_purpose::STANDARD.encode(&public_key_bytes);
            
            // Store the ephemeral secret with its ID
            KEY_CACHE.lock().unwrap().insert(key_id.clone(), secret);
            
            std::result::Result::Ok(HttpResponse::Ok().json(KeyPairResponse {
                key_id,
                public_key: public_key_b64,
            }))
        },
        Err(e) => {
            error!("Failed to generate key pair: {}", e);
            Err(ApiError::InternalError("Failed to generate key pair".into()).into())
        }
    }
}

// Generate a shared secret using a stored ephemeral secret and recipient public key
#[post("/shared-secret")]
pub async fn generate_shared_secret_handler(
    req: web::Json<SharedSecretRequest>,
) -> Result<HttpResponse, Error> {
    let recipient_public_bytes = match general_purpose::STANDARD.decode(&req.recipient_public_key) {
        std::result::Result::Ok(bytes) => bytes,
        Err(_) => return Err(ApiError::BadRequest("Invalid public key format".into()).into()),
    };
    
    let recipient_public = match PublicKey::from_sec1_bytes(&recipient_public_bytes) {
        std::result::Result::Ok(key) => key,
        Err(_) => return Err(ApiError::BadRequest("Invalid public key".into()).into()),
    };
    
    let mut cache = KEY_CACHE.lock().unwrap();
    let ephemeral_secret = match cache.get(&req.key_id) {
        Some(secret) => secret,
        None => return Err(ApiError::NotFound("Key not found or expired".into()).into()),
    };
    
    match generate_shared_secret(ephemeral_secret, &recipient_public) {
        std::result::Result::Ok(shared_secret) => {
            let shared_secret_bytes = shared_secret.raw_secret_bytes();
            let shared_secret_b64 = general_purpose::STANDARD.encode(&shared_secret_bytes);
            
            std::result::Result::Ok(HttpResponse::Ok().json(SharedSecretResponse {
                shared_secret: shared_secret_b64,
            }))
        },
        Err(e) => {
            error!("Failed to generate shared secret: {}", e);
            Err(ApiError::InternalError("Failed to generate shared secret".into()).into())
        }
    }
}

// Get the public key for a given key ID
#[get("/public-key/{key_id}")]
pub async fn get_recipient_public_key_handler(key_id: web::Path<String>) -> Result<HttpResponse, Error> {
    let mut cache = KEY_CACHE.lock().unwrap();
    let ephemeral_secret = match cache.get(&key_id) {
        Some(secret) => secret,
        None => return Err(ApiError::NotFound("Key not found or expired".into()).into()),
    };
    
    let public_key = get_recipient_public_key(ephemeral_secret);
    let public_key_bytes = public_key.to_sec1_bytes();
    let public_key_b64 = general_purpose::STANDARD.encode(&public_key_bytes);
    
    std::result::Result::Ok(HttpResponse::Ok().json(PublicKeyResponse {
        public_key: public_key_b64,
    }))
}

// Encrypt a file using a recipient's public key
#[post("/encrypt")]
pub async fn encrypt_file_handler(
    mut payload: Multipart,
    req_query: web::Query<EncryptionRequest>,
) -> Result<HttpResponse, Error> {
    // Create temporary directory for file processing
    let tmp_dir = tempdir().map_err(|e| {
        error!("Failed to create temp directory: {}", e);
        ApiError::InternalError("Failed to process file".into())
    })?;
    
    // Parse the recipient's public key
    let recipient_public_bytes = match general_purpose::STANDARD.decode(&req_query.recipient_public_key) {
        std::result::Result::Ok(bytes) => bytes,
        Err(_) => return Err(ApiError::BadRequest("Invalid public key format".into()).into()),
    };
    
    let recipient_public = match PublicKey::from_sec1_bytes(&recipient_public_bytes) {
        std::result::Result::Ok(key) => key,
        Err(_) => return Err(ApiError::BadRequest("Invalid public key".into()).into()),
    };
    
    // Process the uploaded file
    let mut input_path = None;
    
    while let Some(mut field) = payload.try_next().await.map_err(|e| {
        error!("Error processing multipart: {}", e);
        ApiError::BadRequest("Invalid multipart form data".into())
    })? {
        if field.name() == "file" {
            let file_path = tmp_dir.path().join("input_file");
            let mut file = web::block(|| std::fs::File::create(&file_path))
                .await
                .map_err(|e| {
                    error!("Failed to create temp file: {:?}", e);
                    ApiError::InternalError("Failed to process file".into())
                })?;
                
            while let Some(chunk) = field.try_next().await.map_err(|e| {
                error!("Error reading field chunk: {}", e);
                ApiError::BadRequest("Failed to read file data".into())
            })? {
                let chunk = chunk.to_vec();
                let path = file_path.clone();
                 web::block(move ||  {
                    use std::io::Write;
                    let mut f = std::fs::OpenOptions::new()
                    .append(true)
                    .open(&path)?;
                    f.write_all(&chunk)?;
                    std::result::Result::Ok::<_, std::io::Error>(())
                 }
                    ).await
                    .map_err(|e| {
                        error!("Failed to write to temp file: {:?}", e);
                        ApiError::InternalError("failed to process file".into())
                    })?;
            }
            
            input_path = Some(file_path);
        }
    }
    
    let input_path = input_path.ok_or_else(|| {
        ApiError::BadRequest("No file provided".into())
    })?;
    
    // Generate a unique ID for the encrypted file
    let file_id = Uuid::new_v4().to_string();
    let output_path = tmp_dir.path().join(format!("encrypted_{}", file_id));
    
    // Encrypt the file
    web::block(move || {
        encrypt_file(&input_path, &output_path, &recipient_public)
    })
    .await
    .map_err(|e| {
        error!("Encryption failed: {:?}", e);
        ApiError::InternalError("Failed to encrypt file".into())
    })?;
    
    // Read the encrypted file to send it back
    let encrypted_data = web::block(move || std::fs::read(output_path))
        .await
        .map_err(|e| {
            error!("Failed to read encrypted file: {:?}", e);
            ApiError::InternalError("Failed to read encrypted data".into())
        })?;
    
    // Return the encrypted data
    Ok(HttpResponse::Ok()
    .content_type("application/octet-stream")
    .append_header(("Content-Disposition", format!("attachment; filename=\"encrypted_{}.bin\"", file_id)))
    .body(encrypted_data))
}

// Decrypt a file using a stored ephemeral secret
#[post("/decrypt/{key_id}")]
pub async fn decrypt_file_handler(
    mut payload: Multipart,
    key_id: web::Path<String>,
) -> Result<HttpResponse, Error> {
    // Create temporary directory for file processing
    let tmp_dir = tempdir().map_err(|e| {
        error!("Failed to create temp directory: {}", e);
        ApiError::InternalError("Failed to process file".into())
    })?;
    
    // Get the ephemeral secret
    let key_id = key_id.into_inner();
    let ephemeral_secret = {
        let mut cache = KEY_CACHE.lock().unwrap();
        match cache.get(&key_id) {
            Some(secret) => secret.clone(),
            None => return Err(ApiError::NotFound("Key not found or expired".into()).into()),
        }
    };
    
    // Process the uploaded file
    let mut input_path = None;
    
    while let Some(mut field) = payload.try_next().await.map_err(|e| {
        error!("Error processing multipart: {}", e);
        ApiError::BadRequest("Invalid multipart form data".into())
    })? {
        if field.name() == "file" {
            let file_path = tmp_dir.path().join("encrypted_file");
            let mut file = web::block(|| std::fs::File::create(&file_path))
                .await
                .map_err(|e| {
                    error!("Failed to create temp file: {:?}", e);
                    ApiError::InternalError("Failed to process file".into())
                })?;
                
            while let Some(chunk) = field.try_next().await.map_err(|e| {
                error!("Error reading field chunk: {}", e);
                ApiError::BadRequest("Failed to read file data".into())
            })? {
                file = web::block(move || file.write_all(&chunk).map(|_| file))
                    .await
                    .map_err(|e| {
                        error!("Failed to write to temp file: {:?}", e);
                        ApiError::InternalError("Failed to process file".into())
                    })?;
            }
            
            input_path = Some(file_path);
        }
    }
    
    let input_path = input_path.ok_or_else(|| {
        ApiError::BadRequest("No file provided".into())
    })?;
    
    let output_path = tmp_dir.path().join("decrypted_file");
    
    // Decrypt the file
    web::block(move || {
        decrypt_file(&input_path, &output_path, &ephemeral_secret)
    })
    .await
    .map_err(|e| {
        error!("Decryption failed: {:?}", e);
        ApiError::InternalError("Failed to decrypt file".into())
    })?;
    
    // Read the decrypted file to send it back
    let decrypted_data = web::block(move || std::fs::read(output_path))
        .await
        .map_err(|e| {
            error!("Failed to read decrypted file: {:?}", e);
            ApiError::InternalError("Failed to read decrypted data".into())
        })?;
    
    // Return the decrypted data
    std::result::Result::Ok(HttpResponse::Ok()
        .content_type("application/octet-stream")
        .append_header(("Content-Disposition", "attachment; filename=\"decrypted_file\""))
        .body(decrypted_data))
}

// Health check endpoint
#[get("/health")]
pub async fn health_check() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}
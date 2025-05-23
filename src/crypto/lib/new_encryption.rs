use anyhow::{anyhow, Ok, Result};
use bson::{doc, DateTime as BsonDateTime};
use chrono::{DateTime, Utc};
use mongodb::{Client, Collection, Database};
use p256::{
    ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey}, elliptic_curve::Curve, pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey}
};
use p384::{
    ecdsa::{SigningKey as P384SigningKey, VerifyingKey as P384VerifyingKey, Signature as P384Signature},
    pkcs8::{EncodePrivateKey as P384EncodePrivateKey, DecodePrivateKey as P384DecodePrivateKey, 
            EncodePublicKey as P384EncodePublicKey, DecodePublicKey as P384DecodePublicKey},
};
use rand_core::OsRng;
use rocket::{State, get, post, delete, routes, launch, serde::json::Json};
use serde::{Deserialize, Serialize};
use sui_sdk::types::signature;
use std::fmt;
use uuid::Uuid;

pub enum CurveType {
    #[serde(rename = "P-256")]
    P256,
    #[serde(rename = "P-384")]
    P384,
}

impl fmt::Display for CurveType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CurveType::P256 => write!(f, "P-256"),
            CurveType::P384 => write!(f, "P-384"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPairDocument {
    #[serde(rename = "_id")]
    pub id: String,
    pub key_id: String,
    pub private_key: String,
    pub public_key: String,
    pub curve_name: CurveType,
    pub created_at: BsonDateTime,
    pub description: Option<String>,
    pub is_active: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateKeyRequest {
    pub key_id: String,
    pub curve_type: CurveType,
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignRequest {
    pub key_id: String,
    pub message: String, // base64 encoded
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyRequest {
    pub key_id: String,
    pub message: String,    // base64 encoded
    pub signature: String,  // base64 encoded
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyListResponse {
    pub keys: Vec<KeyInfo>,
    pub total: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyInfo {
    pub key_id: String,
    pub curve_name: CurveType,
    pub created_at: DateTime<Utc>,
    pub description: Option<String>,
    pub is_active: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub message: String,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            message: "Operation successful".to_string(),
        }
    }

    pub fn error(message: String) -> Self {
        Self {
            success: false,
            data: None,
            message,
        }
    }
}

pub enum EccKeyPair {
    P256 {
        private_key: P256SigningKey,
        public_key: P256VerifyingKey,
    },
    P384 {
        private_key: P384SigningKey,
        public_key: P384VerifyingKey,
    },
}

impl EccKeyPair {
    pub fn curve_type(&self) -> CurveType {
        match self {
            EccKeyPair::P256 { .. } => CurveType::P256,
            EccKeyPair::P384 { .. } => CurveType::P384,
        }
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        match self {
            EccKeyPair::P256 { private_key, .. } => {
                use p256::ecdsa::signature::Signer;
                let signature: P384Signature = private_key.sign(message);
                Ok(signature.to_bytes().to_vec())
            }
            EccKeyPair::P384 { private_key, .. } => {
                use p384::ecdsa::signature::Signer;
                let signature: P384Signature = private_key.sign(message);
                Ok(signature.to_bytes().to_vec())
            }
        }
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        match self {
            EccKeyPair::P256 { private_key, .. } => {
                use p256::ecdsa::signature::Verifier;
                let sig = P256Signature::try_from(signature)
                    .map_err(|e| anyhow!("Invalid P256 signature: {}", e))?;
                Ok(public_key.verify(message, &sig).is_ok())
            }
            EccKeyPair::P384 { public_key, .. } => {
                use p384::ecdsa::signature::Verifier;
                let sig = P384Signature::try_from(signature)
                .map_err(|e| anyhow!("Invalid P384 signature: {}", e))?;
                Ok(public_key.verify(message, &sig).is_ok())
            }
        }
    }

    pub fn get_private_key_pem(&self) -> Result<String> {
        match self {
            EccKeyPair::P256 { private_key, .. } => {
                private_key.to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
                .map(|s| s.to_string())
                .map_err(|e| anyhow!("Failed to encode P256 private key: {}", e))
            }
            EccKeyPair::P384 { private_key, .. } => {
                private_key.to_pkcs8_pem(p384::pkcs8::LineEnding::LF)
                    .map(|s| s.to_string())
                    .map_err(|e| anyhow!("Failed to encode P384 private key: {}", e))
            }
        }
    }

    pub fn get_public_key_pem(&self) -> Result<String> {
        match self {
            EccKeyPair::P256 { public_key, .. } => {
                public_key.to_public_key_pem(p256::pkcs8::LineEnding::LF)
                    .map_err(|e| anyhow!("Failed to encode P256 public key: {}", e))
            }
            EccKeyPair::P384 { public_key, .. } => {
                public_key.to_public_key_pem(p384::pkcs8::LineEnding::LF)
                    .map_err(|e| anyhow!("Failed to encode P384 public key: {}", e))
            }
        }
    }
}

pub struct EccKeyManager {
    collection: Collection<KeyPairDocument>,
}

impl EccKeyManager {
    pub async fn new(database: &Database) -> Self {
        let collection = database.collection::<KeyPairDocument>("ecc_keys");
        
        // Create indexes for better performance
        let _ = collection
            .create_index(doc! {"key_id": 1}, None)
            .await;
        let _ = collection
            .create_index(doc! {"created_at": -1}, None)
            .await;
        let _ = collection
            .create_index(doc! {"is_active": 1}, None)
            .await;

        Self { collection }
    }

    pub fn generate_key_pair(curve_type: CurveType) -> Result<EccKeyPair> {
        match curve_type {
            CurveType::P256 => {
                let private_key = P256SigningKey::random(&mut OsRng);
                let public_key = P256VerifyingKey::from(&private_key);
                Ok(EccKeyPair::P256 { private_key, public_key })
            }
            CurveType::P384 => {
                let private_key = P384SigningKey::random(&mut OsRng);
                let public_key = P384VerifyingKey::from(&private_key);
                Ok(EccKeyPair::P384 { private_key, public_key })
            }
        }
    }

    pub async fn save_key_pair(
        &self,
        key_id: &str,
        curve_type: CurveType,
        description: Option<String>,
    ) -> Result<String> {
        // Check if key already exists
        if self.key_exists(key_id).await? {
            return Err(anyhow!("Key with ID '{}' already exists", key_id));
        }

        let key_pair = Self::generate_key_pair(curve_type.clone())?;
        
        let private_pem = key_pair.get_private_key_pem()?;
        let public_pem = key_pair.get_public_key_pem()?;

        let document = KeyPairDocument {
            id: Uuid::new_v4().to_string(),
            key_id: key_id.to_string(),
            private_key: private_pem,
            public_key: public_pem,
            curve_name: curve_type,
            created_at: BsonDateTime::now(),
            description,
            is_active: true,
        };

        self.collection.insert_one(&document, None).await
            .map_err(|e| anyhow!("Failed to save key pair '{}': {}", key_id, e))?;

        Ok(document.id)
    }

    pub async fn load_key_pair(&self, key_id: &str) -> Result<Option<EccKeyPair>> {
        let filter = doc! {"key_id": key_id, "is_active": true};
        let document = self.collection.find_one(filter, None).await?;

        if let Some(doc) = document {
            let key_pair = match doc.curve_name {
                CurveType::P256 => {
                    let private_key = P256SigningKey::from_pkcs8_pem(&doc.private_key)
                        .map_err(|e| anyhow!("Failed to decode P256 private key: {}", e))?;
                    let public_key = P256VerifyingKey::from_public_key_pem(&doc.public_key)
                        .map_err(|e| anyhow!("Failed to decode P256 public key: {}", e))?;
                    EccKeyPair::P256 { private_key, public_key }
                }
                CurveType::P384 => {
                    let private_key = P384SigningKey::from_pkcs8_pem(&doc.private_key)
                        .map_err(|e| anyhow!("Failed to decode P384 private key: {}", e))?;
                    let public_key = P384VerifyingKey::from_public_key_pem(&doc.public_key)
                        .map_err(|e| anyhow!("Failed to decode P384 public key: {}", e))?;
                    EccKeyPair::P384 { private_key, public_key }
                }
            };

            Ok(Some(key_pair))
        } else {
            Ok(None)
        }
    }

    pub async fn list_keys(&self) -> Result<Vec<KeyInfo>> {
        let filter = doc! {"is_active": true};
        let mut cursor = self.collection
            .find(filter, None)
            .await?;

        let mut keys = Vec::new();
        while cursor.advance().await? {
            let doc = cursor.deserialize_current()?;
            keys.push(KeyInfo {
                key_id: doc.key_id,
                curve_name: doc.curve_name,
                created_at: doc.created_at.to_chrono(),
                description: doc.description,
                is_active: doc.is_active,
            });
        }

        // Sort by creation date (newest first)
        keys.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        Ok(keys)
    }

    pub async fn deactivate_key_pair(&self, key_id: &str) -> Result<bool> {
        let filter = doc! {"key_id": key_id};
        let update = doc! {"$set": {"is_active": false}};
        
        let result = self.collection.update_one(filter, update, None).await?;
        Ok(result.modified_count > 0)
    }

    pub async fn delete_key_pair(&self, key_id: &str) -> Result<bool> {
        let filter = doc! {"key_id": key_id};
        let result = self.collection.delete_one(filter, None).await?;
        Ok(result.deleted_count > 0)
    }

    pub async fn key_exists(&self, key_id: &str) -> Result<bool> {
        let filter = doc! {"key_id": key_id, "is_active": true};
        let count = self.collection.count_documents(filter, None).await?;
        Ok(count > 0)
    }

}
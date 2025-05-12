use serde::{Deserialize, Serialize};

use crate::models::key::Algorithm;

#[derive(Debug, Deserialize, Serialize)]
pub struct GenerateKeypairRequest {
    pub password: String,
    pub user: String,       // MongoDB ObjectId as string
    pub algorithm: Algorithm,  // e.g., "AES", "RSA", etc.
}
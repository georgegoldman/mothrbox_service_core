use mongodb::bson::{oid::ObjectId, DateTime};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub enum Algorithm {
    XOR,
    AES,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyPair {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    #[serde(rename = "user")]
    pub owner: ObjectId, // Reference to User document

    // #[serde(skip_serializing_if = "Option::is_none")]
    pub r#algorithm: Option<Algorithm>, // Optional enum field

    pub alias: String,

    pub value: Vec<u8>,

    #[serde(default = "default_is_active")]
    pub is_active: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime>,
}

fn default_is_active() -> bool {
    true
}

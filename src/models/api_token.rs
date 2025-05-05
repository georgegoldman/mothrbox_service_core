use serde::{Serialize, Deserialize};
use mongodb::bson::{oid::ObjectId, DateTime};
use sui_sdk::types::base_types::SuiAddress;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ApiToken {
    #[serde(rename = "_id")]
    pub id: ObjectId,

    pub token: String,
    pub allowed: bool,
    pub owner: SuiAddress,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime>,
}

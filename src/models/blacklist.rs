use mongodb::bson::{doc, DateTime};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct BlackListedToken {
    pub token: String,
    pub blacklist_at: DateTime
}

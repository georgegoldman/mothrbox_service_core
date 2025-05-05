use serde::{Deserialize};
use sui_sdk::types::base_types::SuiAddress;

#[derive(Deserialize)]
pub struct KeyPairDTO {
    pub address: SuiAddress
}
